package client

import (
	"strings"
	"testing"

	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
)

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
