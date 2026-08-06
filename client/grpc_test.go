package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	cloudservicev1 "go.temporal.io/cloud-sdk/api/cloudservice/v1"
	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
	"google.golang.org/grpc"
)

// fakeCloudServiceClient embeds the generated client interface without a
// value, so any method this test doesn't override panics loudly if called —
// FindServiceAccountByName only ever needs GetServiceAccounts.
type fakeCloudServiceClient struct {
	cloudservicev1.CloudServiceClient
	getServiceAccountsFn func(ctx context.Context, req *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error)
}

func (f *fakeCloudServiceClient) GetServiceAccounts(ctx context.Context, req *cloudservicev1.GetServiceAccountsRequest, _ ...grpc.CallOption) (*cloudservicev1.GetServiceAccountsResponse, error) {
	return f.getServiceAccountsFn(ctx, req)
}

// TestFindServiceAccountByName_Found covers the ordinary match, including
// that the SINGULAR getter (GetServiceAccount, despite the plural field) is
// what carries the results.
func TestFindServiceAccountByName_Found(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(context.Context, *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			return &cloudservicev1.GetServiceAccountsResponse{
				ServiceAccount: []*identityv1.ServiceAccount{
					{Id: "sa-other", Spec: &identityv1.ServiceAccountSpec{Name: "other"}},
					{Id: "sa-match", Spec: &identityv1.ServiceAccountSpec{Name: "prod-workers"}},
				},
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sa-match" {
		t.Errorf("expected sa-match, got %q", got.ID)
	}
}

// TestFindServiceAccountByName_NotFound covers exhausting every page with no
// match, which must return ErrNotFound rather than a generic error so the
// write path can distinguish "free to create" from "lookup broke."
func TestFindServiceAccountByName_NotFound(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(context.Context, *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			return &cloudservicev1.GetServiceAccountsResponse{
				ServiceAccount: []*identityv1.ServiceAccount{
					{Id: "sa-other", Spec: &identityv1.ServiceAccountSpec{Name: "other"}},
				},
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	_, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestFindServiceAccountByName_PagesThrough confirms a match on a later page
// is not missed just because the first page didn't have it.
func TestFindServiceAccountByName_PagesThrough(t *testing.T) {
	calls := 0
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(_ context.Context, req *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			calls++
			if req.GetPageToken() == "" {
				return &cloudservicev1.GetServiceAccountsResponse{
					ServiceAccount: []*identityv1.ServiceAccount{
						{Id: "sa-1", Spec: &identityv1.ServiceAccountSpec{Name: "alpha"}},
					},
					NextPageToken: "page-2",
				}, nil
			}
			return &cloudservicev1.GetServiceAccountsResponse{
				ServiceAccount: []*identityv1.ServiceAccount{
					{Id: "sa-2", Spec: &identityv1.ServiceAccountSpec{Name: "prod-workers"}},
				},
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	got, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "sa-2" {
		t.Errorf("expected sa-2, got %q", got.ID)
	}
	if calls != 2 {
		t.Errorf("expected 2 pages fetched, got %d", calls)
	}
}

// TestFindServiceAccountByName_NonAdvancingPageToken guards against a server
// that returns the same next-page token forever, which would otherwise spin
// this loop with no bound but context cancellation.
func TestFindServiceAccountByName_NonAdvancingPageToken(t *testing.T) {
	fake := &fakeCloudServiceClient{
		getServiceAccountsFn: func(context.Context, *cloudservicev1.GetServiceAccountsRequest) (*cloudservicev1.GetServiceAccountsResponse, error) {
			return &cloudservicev1.GetServiceAccountsResponse{
				NextPageToken: "stuck",
			}, nil
		},
	}
	c := &grpcClient{svc: fake}

	_, err := c.FindServiceAccountByName(context.Background(), "prod-workers")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

// specFromProto must never silently render an unrecognised account role or
// namespace permission as an empty string: an empty AccountRole reads exactly
// like "no role configured," which is a worse failure mode than a visibly odd
// value. This covers ROLE_UNSPECIFIED and PERMISSION_UNSPECIFIED, the case
// accountRoleFromProto/namespacePermissionFromProto (client/access.go) return
// "" for today, and stands in for any future role/permission Temporal Cloud
// adds before this engine's lookup tables catch up.
func TestSpecFromProto_UnmappedRoleAndPermission(t *testing.T) {
	p := &identityv1.ServiceAccountSpec{
		Name:        "svc",
		Description: "test",
		Access: &identityv1.Access{
			AccountAccess: &identityv1.AccountAccess{
				Role: identityv1.AccountAccess_ROLE_UNSPECIFIED,
			},
			NamespaceAccesses: map[string]*identityv1.NamespaceAccess{
				"prod.acct1": {
					Permission: identityv1.NamespaceAccess_PERMISSION_UNSPECIFIED,
				},
			},
		},
	}

	spec := specFromProto(p)

	if spec.AccountRole == "" {
		t.Fatal("expected a non-empty sentinel for an unmapped account role, got empty string")
	}
	if !strings.Contains(spec.AccountRole, "unmapped") {
		t.Fatalf("expected the sentinel to flag itself as unmapped, got %q", spec.AccountRole)
	}

	perm := spec.NamespaceAccess["prod.acct1"]
	if perm == "" {
		t.Fatal("expected a non-empty sentinel for an unmapped namespace permission, got empty string")
	}
	if !strings.Contains(perm, "unmapped") {
		t.Fatalf("expected the sentinel to flag itself as unmapped, got %q", perm)
	}
}
