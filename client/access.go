package client

import (
	"fmt"
	"sort"
	"strings"

	identityv1 "go.temporal.io/cloud-sdk/api/identity/v1"
)

// accountRoles maps the role names an operator writes to their proto values.
// The spellings match the Temporal Cloud CLI so operators can move between
// tcld and Vault without relearning them.
var accountRoles = map[string]identityv1.AccountAccess_Role{
	"owner":         identityv1.AccountAccess_ROLE_OWNER,
	"admin":         identityv1.AccountAccess_ROLE_ADMIN,
	"developer":     identityv1.AccountAccess_ROLE_DEVELOPER,
	"finance-admin": identityv1.AccountAccess_ROLE_FINANCE_ADMIN,
	"read":          identityv1.AccountAccess_ROLE_READ,
	"metrics-read":  identityv1.AccountAccess_ROLE_METRICS_READ,
}

// namespacePermissions maps namespace permission names to their proto values.
var namespacePermissions = map[string]identityv1.NamespaceAccess_Permission{
	"admin": identityv1.NamespaceAccess_PERMISSION_ADMIN,
	"write": identityv1.NamespaceAccess_PERMISSION_WRITE,
	"read":  identityv1.NamespaceAccess_PERMISSION_READ,
}

// ParseAccountRole converts an operator-supplied account role to its proto
// value. Input is trimmed and lowercased, because operators copy values out of
// docs and UIs with inconsistent casing.
func ParseAccountRole(s string) (identityv1.AccountAccess_Role, error) {
	role, ok := accountRoles[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("%w: unknown account_role %q, must be one of: %s",
			ErrInvalidArgument, s, sortedKeys(accountRoles))
	}
	return role, nil
}

// ParseNamespacePermission converts an operator-supplied namespace permission
// to its proto value.
func ParseNamespacePermission(s string) (identityv1.NamespaceAccess_Permission, error) {
	perm, ok := namespacePermissions[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("%w: unknown namespace permission %q, must be one of: %s",
			ErrInvalidArgument, s, sortedKeys(namespacePermissions))
	}
	return perm, nil
}

// accountRoleFromProto renders a role back as the string an operator wrote, so
// reads of service-accounts/<name> echo the input rather than proto constants.
func accountRoleFromProto(role identityv1.AccountAccess_Role) string {
	for name, v := range accountRoles {
		if v == role {
			return name
		}
	}
	return ""
}

// namespacePermissionFromProto is the inverse of ParseNamespacePermission.
func namespacePermissionFromProto(perm identityv1.NamespaceAccess_Permission) string {
	for name, v := range namespacePermissions {
		if v == perm {
			return name
		}
	}
	return ""
}

// toProto converts a spec into the Temporal Cloud representation, validating
// every field. Validation lives here rather than in the Vault path handler so
// there is exactly one place that decides what a valid spec is.
func (s ServiceAccountSpec) toProto() (*identityv1.ServiceAccountSpec, error) {
	if strings.TrimSpace(s.Name) == "" {
		return nil, fmt.Errorf("%w: service account name must not be empty", ErrInvalidArgument)
	}

	role, err := ParseAccountRole(s.AccountRole)
	if err != nil {
		return nil, err
	}

	access := &identityv1.Access{
		AccountAccess: &identityv1.AccountAccess{Role: role},
	}

	if len(s.NamespaceAccess) > 0 {
		access.NamespaceAccesses = make(map[string]*identityv1.NamespaceAccess, len(s.NamespaceAccess))

		for namespace, permission := range s.NamespaceAccess {
			if strings.TrimSpace(namespace) == "" {
				return nil, fmt.Errorf("%w: namespace name must not be empty", ErrInvalidArgument)
			}

			perm, err := ParseNamespacePermission(permission)
			if err != nil {
				return nil, fmt.Errorf("namespace %q: %w", namespace, err)
			}

			access.NamespaceAccesses[namespace] = &identityv1.NamespaceAccess{Permission: perm}
		}
	}

	return &identityv1.ServiceAccountSpec{
		Name:        s.Name,
		Description: s.Description,
		Access:      access,
	}, nil
}

// sortedKeys renders map keys in a stable order so error messages do not
// shuffle between runs.
func sortedKeys[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
