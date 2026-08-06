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

// DeleteAPIKey deliberately omits ResourceVersion, unlike UpdateServiceAccount
// and DeleteServiceAccount above. KeyId already identifies exactly one key;
// ResourceVersion only describes what state that key is in, so leaving it out
// can't target the wrong key. API keys do mutate (see UpdateApiKey — Disabled,
// DisplayName, Description, and ExpiryTime can all change and bump the
// version), and the most likely mutation is an admin disabling a key they
// suspect is compromised. Making revocation conditional on the version would
// let that disable race ahead and make the delete fail, leaving the Vault
// lease unable to revoke a credential it issued. Failing to revoke is worse
// than clobbering a concurrent edit, so this call stays unconditional.
func (c *grpcClient) DeleteAPIKey(ctx context.Context, id string) error {
	resp, err := c.svc.DeleteApiKey(ctx, &cloudservicev1.DeleteApiKeyRequest{
		KeyId: id,
	})
	if err != nil {
		return MapGRPCError(err)
	}

	return awaitOperation(ctx, c.svc, resp.GetAsyncOperation())
}

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
