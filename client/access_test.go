package client

import (
	"errors"
	"strings"
	"testing"

	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
)

func TestParseAccountRole(t *testing.T) {
	tests := []struct {
		in      string
		want    identityv1.AccountAccess_Role
		wantErr bool
	}{
		{"owner", identityv1.AccountAccess_ROLE_OWNER, false},
		{"admin", identityv1.AccountAccess_ROLE_ADMIN, false},
		{"developer", identityv1.AccountAccess_ROLE_DEVELOPER, false},
		{"finance-admin", identityv1.AccountAccess_ROLE_FINANCE_ADMIN, false},
		{"read", identityv1.AccountAccess_ROLE_READ, false},
		{"metrics-read", identityv1.AccountAccess_ROLE_METRICS_READ, false},

		// Operators type inconsistently; accept case and surrounding space.
		{"Developer", identityv1.AccountAccess_ROLE_DEVELOPER, false},
		{"  developer  ", identityv1.AccountAccess_ROLE_DEVELOPER, false},

		{"", 0, true},
		{"superuser", 0, true},
		{"finance_admin", 0, true}, // underscore is not the documented spelling
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseAccountRole(tc.in)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got role %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

// The error must list the valid values, because an operator who typed the
// wrong one needs to know the right ones without opening the docs.
func TestParseAccountRole_ErrorListsValidValues(t *testing.T) {
	_, err := ParseAccountRole("superuser")

	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"owner", "admin", "developer", "finance-admin", "read", "metrics-read"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to mention %q, got: %v", want, err)
		}
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestParseNamespacePermission(t *testing.T) {
	tests := []struct {
		in      string
		want    identityv1.NamespaceAccess_Permission
		wantErr bool
	}{
		{"admin", identityv1.NamespaceAccess_PERMISSION_ADMIN, false},
		{"write", identityv1.NamespaceAccess_PERMISSION_WRITE, false},
		{"read", identityv1.NamespaceAccess_PERMISSION_READ, false},
		{"Write", identityv1.NamespaceAccess_PERMISSION_WRITE, false},
		{"", 0, true},
		{"owner", 0, true}, // an account role, not a namespace permission
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseNamespacePermission(tc.in)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestServiceAccountSpec_ToProto(t *testing.T) {
	spec := ServiceAccountSpec{
		Name:        "prod-workers",
		Description: "managed by vault",
		AccountRole: "developer",
		NamespaceAccess: map[string]string{
			"prod.acct1":    "write",
			"staging.acct1": "read",
		},
	}

	got, err := spec.toProto()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.GetName() != "prod-workers" {
		t.Errorf("expected name prod-workers, got %q", got.GetName())
	}
	if got.GetDescription() != "managed by vault" {
		t.Errorf("expected description to carry through, got %q", got.GetDescription())
	}
	if role := got.GetAccess().GetAccountAccess().GetRole(); role != identityv1.AccountAccess_ROLE_DEVELOPER {
		t.Errorf("expected ROLE_DEVELOPER, got %v", role)
	}

	accesses := got.GetAccess().GetNamespaceAccesses()
	if len(accesses) != 2 {
		t.Fatalf("expected 2 namespace accesses, got %d", len(accesses))
	}
	if p := accesses["prod.acct1"].GetPermission(); p != identityv1.NamespaceAccess_PERMISSION_WRITE {
		t.Errorf("expected PERMISSION_WRITE for prod.acct1, got %v", p)
	}
	if p := accesses["staging.acct1"].GetPermission(); p != identityv1.NamespaceAccess_PERMISSION_READ {
		t.Errorf("expected PERMISSION_READ for staging.acct1, got %v", p)
	}
}

// A service account with no namespace access is valid — account-level role only.
func TestServiceAccountSpec_ToProto_NoNamespaceAccess(t *testing.T) {
	spec := ServiceAccountSpec{Name: "readonly", AccountRole: "read"}

	got, err := spec.toProto()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.GetAccess().GetNamespaceAccesses()) != 0 {
		t.Errorf("expected no namespace accesses, got %d", len(got.GetAccess().GetNamespaceAccesses()))
	}
}

func TestServiceAccountSpec_ToProto_Invalid(t *testing.T) {
	tests := []struct {
		name string
		spec ServiceAccountSpec
	}{
		{"empty name", ServiceAccountSpec{AccountRole: "read"}},
		{"bad account role", ServiceAccountSpec{Name: "x", AccountRole: "wizard"}},
		{
			"bad namespace permission",
			ServiceAccountSpec{Name: "x", AccountRole: "read", NamespaceAccess: map[string]string{"ns.acct": "sudo"}},
		},
		{
			"empty namespace name",
			ServiceAccountSpec{Name: "x", AccountRole: "read", NamespaceAccess: map[string]string{"": "read"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.spec.toProto(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// Round-tripping matters: service-accounts/<name> reads render the stored
// proto back as the strings the operator originally wrote.
func TestRoleAndPermissionRoundTrip(t *testing.T) {
	for _, role := range []string{"owner", "admin", "developer", "finance-admin", "read", "metrics-read"} {
		parsed, err := ParseAccountRole(role)
		if err != nil {
			t.Fatalf("parsing %q: %v", role, err)
		}
		if got := accountRoleFromProto(parsed); got != role {
			t.Errorf("round trip of %q produced %q", role, got)
		}
	}

	for _, perm := range []string{"admin", "write", "read"} {
		parsed, err := ParseNamespacePermission(perm)
		if err != nil {
			t.Fatalf("parsing %q: %v", perm, err)
		}
		if got := namespacePermissionFromProto(parsed); got != perm {
			t.Errorf("round trip of %q produced %q", perm, got)
		}
	}
}
