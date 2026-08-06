package client

import (
	"context"
	"fmt"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	"go.temporal.io/cloud-sdk/cloudclient"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config already exists in client.go from Task 1 — do not redeclare it here.

// grpcClient implements CloudOps against the real Cloud Ops API.
type grpcClient struct {
	conn *cloudclient.Client
	svc  cloudservicev1.CloudServiceClient
}

// NewGRPC builds a CloudOps backed by Temporal Cloud.
//
// The SDK's default interceptors already assign an async_operation_id to every
// write and retry retryable failures with exponential backoff, so this engine
// deliberately adds neither. Setting DisableRetry would remove both.
func NewGRPC(cfg Config) (CloudOps, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("%w: api_key must not be empty", ErrInvalidArgument)
	}

	conn, err := cloudclient.New(cloudclient.Options{
		APIKey:   cfg.APIKey,
		HostPort: cfg.HostPort,
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to temporal cloud: %w", err)
	}

	return &grpcClient{conn: conn, svc: conn.CloudService()}, nil
}

func (c *grpcClient) Close() error {
	return c.conn.Close()
}

func (c *grpcClient) CreateServiceAccount(ctx context.Context, spec ServiceAccountSpec) (string, error) {
	protoSpec, err := spec.toProto()
	if err != nil {
		return "", err
	}

	resp, err := c.svc.CreateServiceAccount(ctx, &cloudservicev1.CreateServiceAccountRequest{
		Spec: protoSpec,
	})
	if err != nil {
		return "", MapGRPCError(err)
	}

	if err := awaitOperation(ctx, c.svc, resp.GetAsyncOperation()); err != nil {
		// The ID is returned before the operation completes, so surface it:
		// the caller may need it to clean up a half-created account.
		return resp.GetServiceAccountId(), err
	}

	return resp.GetServiceAccountId(), nil
}

func (c *grpcClient) GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error) {
	resp, err := c.svc.GetServiceAccount(ctx, &cloudservicev1.GetServiceAccountRequest{
		ServiceAccountId: id,
	})
	if err != nil {
		return nil, MapGRPCError(err)
	}

	sa := resp.GetServiceAccount()
	if sa == nil {
		return nil, fmt.Errorf("%w: service account %s", ErrNotFound, id)
	}

	return &ServiceAccount{
		ID:              sa.GetId(),
		ResourceVersion: sa.GetResourceVersion(),
		Spec:            specFromProto(sa.GetSpec()),
	}, nil
}

func (c *grpcClient) UpdateServiceAccount(ctx context.Context, id string, spec ServiceAccountSpec) error {
	protoSpec, err := spec.toProto()
	if err != nil {
		return err
	}

	// Temporal Cloud uses optimistic concurrency: the update must name the
	// version it is replacing. Fetching it here keeps resource versions out
	// of the CloudOps interface entirely.
	current, err := c.GetServiceAccount(ctx, id)
	if err != nil {
		return err
	}

	resp, err := c.svc.UpdateServiceAccount(ctx, &cloudservicev1.UpdateServiceAccountRequest{
		ServiceAccountId: id,
		Spec:             protoSpec,
		ResourceVersion:  current.ResourceVersion,
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

func (c *grpcClient) DeleteServiceAccount(ctx context.Context, id string) error {
	current, err := c.GetServiceAccount(ctx, id)
	if err != nil {
		return err
	}

	resp, err := c.svc.DeleteServiceAccount(ctx, &cloudservicev1.DeleteServiceAccountRequest{
		ServiceAccountId: id,
		ResourceVersion:  current.ResourceVersion,
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

func (c *grpcClient) CreateAPIKey(ctx context.Context, spec APIKeySpec) (*APIKey, error) {
	if spec.ExpiryTime.IsZero() {
		return nil, fmt.Errorf("%w: api key expiry time is required", ErrInvalidArgument)
	}

	resp, err := c.svc.CreateApiKey(ctx, &cloudservicev1.CreateApiKeyRequest{
		Spec: &identityv1.ApiKeySpec{
			OwnerId:     spec.ServiceAccountID,
			OwnerType:   identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT,
			DisplayName: spec.DisplayName,
			Description: spec.Description,
			ExpiryTime:  timestamppb.New(spec.ExpiryTime),
		},
	})
	if err != nil {
		return nil, MapGRPCError(err)
	}

	if err := awaitOperation(ctx, c.svc, resp.GetAsyncOperation()); err != nil {
		return nil, err
	}

	// The token is on the create response and is never retrievable again.
	return &APIKey{ID: resp.GetKeyId(), Token: resp.GetToken()}, nil
}

// DeleteAPIKey fetches the current ResourceVersion immediately before
// deleting, unlike the unconditional unversioned call an earlier version of
// this method made.
//
// That earlier version omitted ResourceVersion on the theory that KeyId
// alone already identifies exactly one key, so a version couldn't be needed
// to target the right one. Live testing during Task 8 disproved that: the
// Cloud Ops API rejects DeleteApiKey outright when ResourceVersion is empty,
// with "invalid argument: invalid resource version" — the field is
// mandatory, not merely an optional optimistic-concurrency check. So a
// version must be supplied; the only choice left is how fresh. Fetching it
// right here, right before the call (same pattern as DeleteServiceAccount
// above), keeps the race window against a concurrent mutation — most likely
// an admin disabling a key they suspect is compromised — as small as this
// package can make it.
func (c *grpcClient) DeleteAPIKey(ctx context.Context, id string) error {
	got, err := c.svc.GetApiKey(ctx, &cloudservicev1.GetApiKeyRequest{KeyId: id})
	if err != nil {
		return MapGRPCError(err)
	}

	resp, err := c.svc.DeleteApiKey(ctx, &cloudservicev1.DeleteApiKeyRequest{
		KeyId:           id,
		ResourceVersion: got.GetApiKey().GetResourceVersion(),
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

// CountAPIKeys counts every key GetApiKeys returns, with no filtering on
// ApiKey.State. This is deliberate, not an open question: the count is safe
// in both directions it could be wrong.
//
//   - If GetApiKeys already omits keys that no longer occupy one of the 20
//     slots (RESOURCE_STATE_EXPIRED / _DELETED), this count is exact.
//   - If it does not, this count OVERcounts. An overcount can only make a
//     mint fail early against our own ceiling message — recoverable, and the
//     operator is told exactly why.
//
// The alternative — filtering to RESOURCE_STATE_ACTIVE — risks the opposite,
// worse failure: UNDERcounting. A disabled/suspended key is NOT
// RESOURCE_STATE_ACTIVE but still occupies a slot (proved live by
// TestLive_CountDisabledKey in acceptance_test.go, which disables a key and
// asserts it is still counted). Filtering it out would let a mint slip past
// the real ceiling and land on a raw ResourceExhausted from the server
// instead of our actionable error. So: never filter to ACTIVE-only. If
// filtering is ever added here, it must exclude only
// RESOURCE_STATE_EXPIRED/_DELETED and keep every other state, disabled keys
// included.
func (c *grpcClient) CountAPIKeys(ctx context.Context, serviceAccountID string) (int, error) {
	count := 0
	pageToken := ""

	// The cap applies to non-expired keys, and the API pages, so count every
	// page rather than trusting the first one.
	for {
		resp, err := c.svc.GetApiKeys(ctx, &cloudservicev1.GetApiKeysRequest{
			OwnerId:   serviceAccountID,
			OwnerType: identityv1.OwnerType_OWNER_TYPE_SERVICE_ACCOUNT,
			PageSize:  100,
			PageToken: pageToken,
		})
		if err != nil {
			return 0, MapGRPCError(err)
		}

		count += len(resp.GetApiKeys())

		nextPageToken := resp.GetNextPageToken()
		if nextPageToken == "" {
			return count, nil
		}
		// A misbehaving server could return the same token forever, spinning
		// this loop on the credential-issuing path with no bound but context
		// cancellation. Fail loudly rather than risk an undercount that lets
		// a mint slip past the 20-key ceiling.
		if nextPageToken == pageToken {
			return 0, fmt.Errorf("%w: GetApiKeys page token did not advance", ErrUnavailable)
		}
		pageToken = nextPageToken
	}
}

func (c *grpcClient) FindServiceAccountByName(ctx context.Context, name string) (*ServiceAccount, error) {
	pageToken := ""

	// There is no lookup-by-name RPC, so page through and match. Accounts are
	// few (Temporal Cloud accounts hold tens, not thousands), so this stays
	// cheap, and it only runs when creating a new binding.
	for {
		resp, err := c.svc.GetServiceAccounts(ctx, &cloudservicev1.GetServiceAccountsRequest{
			PageSize:  100,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, MapGRPCError(err)
		}

		// Note the SINGULAR getter on a repeated field — a generated-code quirk.
		for _, sa := range resp.GetServiceAccount() {
			if sa.GetSpec().GetName() != name {
				continue
			}
			return &ServiceAccount{
				ID:              sa.GetId(),
				ResourceVersion: sa.GetResourceVersion(),
				Spec:            specFromProto(sa.GetSpec()),
			}, nil
		}

		nextPageToken := resp.GetNextPageToken()
		if nextPageToken == "" {
			return nil, fmt.Errorf("%w: no service account named %q", ErrNotFound, name)
		}
		// Same non-advancing-token guard as CountAPIKeys: a server that stops
		// advancing would otherwise spin this loop forever.
		if nextPageToken == pageToken {
			return nil, fmt.Errorf("%w: GetServiceAccounts page token did not advance", ErrUnavailable)
		}
		pageToken = nextPageToken
	}
}

// specFromProto renders a Temporal Cloud service account spec back into the
// plain strings an operator wrote.
func specFromProto(p *identityv1.ServiceAccountSpec) ServiceAccountSpec {
	role := p.GetAccess().GetAccountAccess().GetRole()
	accountRole := accountRoleFromProto(role)
	if accountRole == "" {
		// See unmappedRole's doc comment: an empty string here would make an
		// unrecognised role look identical to "no role set".
		accountRole = unmappedRole(role)
	}

	spec := ServiceAccountSpec{
		Name:        p.GetName(),
		Description: p.GetDescription(),
		AccountRole: accountRole,
	}

	accesses := p.GetAccess().GetNamespaceAccesses()
	if len(accesses) > 0 {
		spec.NamespaceAccess = make(map[string]string, len(accesses))
		for namespace, access := range accesses {
			perm := access.GetPermission()
			permission := namespacePermissionFromProto(perm)
			if permission == "" {
				permission = unmappedNamespacePermission(perm)
			}
			spec.NamespaceAccess[namespace] = permission
		}
	}

	return spec
}

// unmappedRole and unmappedNamespacePermission cover a gap in
// accountRoleFromProto/namespacePermissionFromProto (client/access.go): those
// helpers reverse-scan a lookup table and return "" for any proto value they
// don't recognise, which includes both ROLE_UNSPECIFIED/PERMISSION_UNSPECIFIED
// and any role or permission Temporal Cloud adds server-side before this
// engine's table is updated. Propagating "" unchanged into a read response
// would render an unknown role indistinguishable from "no role" — the field
// would just look empty. A service account always has *some* role; we simply
// don't have a name for this one. Render a clearly-marked, non-empty string
// carrying the raw proto enum instead, so `vault read service-accounts/<name>`
// surfaces "something we don't recognise" rather than "nothing at all".
func unmappedRole(role identityv1.AccountAccess_Role) string {
	return fmt.Sprintf("unmapped-role(%s)", role)
}

func unmappedNamespacePermission(perm identityv1.NamespaceAccess_Permission) string {
	return fmt.Sprintf("unmapped-permission(%s)", perm)
}
