package connector

import (
	"context"
	"errors"
	"fmt"

	"strings"

	onepassword "github.com/conductorone/baton-1password/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

func AllVaultPermissions() mapset.Set[string] {
	rv := mapset.NewSet[string]()
	rv.Add(memberEntitlement)
	for permission := range basicPermissions {
		rv.Add(permission)
	}
	for permission := range businessPermissions {
		rv.Add(permission)
	}
	return rv
}

// 1Password Teams and 1Password Families.
var basicPermissions = map[string]string{
	"allow_viewing":  "allow viewing",
	"allow_editing":  "allow editing",
	"allow_managing": "allow managing",
}

// 1Password Business.
var businessPermissions = map[string]string{
	"view_items":              "view items",
	"create_items":            "create items",
	"edit_items":              "edit items",
	"archive_items":           "archive items",
	"delete_items":            "delete items",
	"view_and_copy_passwords": "view and copy passwords",
	"view_item_history":       "view item history",
	"import_items":            "import items",
	"export_items":            "export items",
	"copy_and_share_items":    "copy and share items",
	"print_items":             "print items",
	"manage_vault":            "manage vault",
}

// Map of permissions to their dependencies.
// This is used to determine the permissions that need to be granted when a user is granted a permission.
var dependencyMap = map[string][]string{
	"create_items":            {"view_items"},
	"view_and_copy_passwords": {"view_items"},
	"edit_items":              {"view_and_copy_passwords", "view_items"},
	"archive_items":           {"edit_items", "view_and_copy_passwords", "view_items"},
	"delete_items":            {"edit_items", "view_and_copy_passwords", "view_items"},
	"view_item_history":       {"view_and_copy_passwords", "view_items"},
	"import_items":            {"create_items", "view_items"},
	"export_items":            {"view_item_history", "view_and_copy_passwords", "view_items"},
	"copy_and_share_items":    {"view_item_history", "view_and_copy_passwords", "view_items"},
	"print_items":             {"view_item_history", "view_and_copy_passwords", "view_items"},
	"allow_editing":           {"allow_viewing"},
}

// Used to determine the permissions to revoke when a user's permission is revoked.
var reverseDependencyMap = map[string][]string{
	"view_items": {"create_items", "view_and_copy_passwords", "edit_items", "archive_items", "delete_items", "import_items",
		"export_items", "copy_and_share_items", "print_items"},
	"view_and_copy_passwords": {"edit_items", "archive_items", "delete_items", "view_item_history", "export_items", "copy_and_share_items", "print_items"},
	"edit_items":              {"archive_items", "delete_items"},
	"view_item_history":       {"export_items", "copy_and_share_items", "print_items"},
	"create_items":            {"import_items"},
	"allow_viewing":           {"allow_editing"},
}

// resolveDeps recursively resolves all dependencies of a given permission.
// It traverses the dependency graph using depMap, tracking visited permissions
// with the seen map to avoid cycles and duplicates.
// Returns a list of all dependencies plus the permission itself, in order.
func resolveDeps(permission string, depMap map[string][]string, seen map[string]bool) []string {
	if seen[permission] {
		return nil
	}
	seen[permission] = true

	deps := []string{}
	for _, dep := range depMap[permission] {
		deps = append(deps, resolveDeps(dep, depMap, seen)...)
	}
	deps = append(deps, permission)
	return deps
}

// expandPermissions returns the full list of permissions required by
// expanding the dependencies of the given permission based on dependencyMap.
// It ensures no duplicates by tracking visited permissions.
func expandPermissions(permission string) []string {
	seen := make(map[string]bool)
	return resolveDeps(permission, dependencyMap, seen)
}

// expandPermissionsForRevoke returns the full list of permissions that depend
// on the given permission, based on reverseDependencyMap. This is useful
// for revoking permissions because it identifies all dependent permissions
// that must also be revoked. It returns a unique set of permissions.
func expandPermissionsForRevoke(permission string) []string {
	seen := make(map[string]bool)
	deps := resolveDeps(permission, reverseDependencyMap, seen)

	unique := mapset.NewSet[string]()
	for _, p := range deps {
		unique.Add(p)
	}
	return unique.ToSlice()
}

const businessAccountType = "BUSINESS"

type vaultResourceType struct {
	resourceType          *v2.ResourceType
	cli                   *onepassword.OnePasswordClient
	limitVaultPermissions mapset.Set[string]
}

func (g *vaultResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for a 1Password vault.
func vaultResource(vault onepassword.Vault, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	ret, err := resource.NewResource(
		vault.Name,
		resourceTypeVault,
		vault.ID,
		resource.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *vaultResourceType) List(ctx context.Context, parentId *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentId == nil {
		return nil, "", nil, nil
	}

	var rv []*v2.Resource

	vaults, err := g.cli.ListVaults(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	for _, vault := range vaults {
		vaultCopy := vault
		gr, err := vaultResource(vaultCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, gr)
	}

	return rv, "", nil, nil
}

func (g *vaultResourceType) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	account, err := g.cli.GetAccount(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	memberOptions := PopulateOptions(resource.DisplayName, memberEntitlement, resource.Id.ResourceType)
	membetEnt := ent.NewAssignmentEntitlement(resource, memberEntitlement, memberOptions...)
	if g.limitVaultPermissions != nil {
		if g.limitVaultPermissions.Contains(memberEntitlement) {
			rv = append(rv, membetEnt)
		}
	} else {
		rv = append(rv, membetEnt)
	}

	// Business accounts have more granular permissions.
	if account.Type == businessAccountType {
		for permName, permission := range businessPermissions {
			if g.limitVaultPermissions != nil {
				if !g.limitVaultPermissions.Contains(permName) {
					continue
				}
			}
			businessOptions := PopulateOptions(resource.DisplayName, permission, resource.Id.ResourceType)
			businessEntitlement := ent.NewPermissionEntitlement(resource, permission, businessOptions...)
			rv = append(rv, businessEntitlement)
		}
	} else {
		for permName, permission := range basicPermissions {
			if g.limitVaultPermissions != nil {
				if !g.limitVaultPermissions.Contains(permName) {
					continue
				}
			}
			basicOptions := PopulateOptions(resource.DisplayName, permission, resource.Id.ResourceType)
			basicEntitlement := ent.NewPermissionEntitlement(resource, permission, basicOptions...)
			rv = append(rv, basicEntitlement)
		}
	}

	return rv, "", nil, nil
}

const (
	vaultListUsersOp  = "vault-list-users"
	vaultListGroupsOp = "vault-list-groups"
)

func (g *vaultResourceType) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pToken.Token)
	if err != nil {
		return nil, "", nil, err
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: vaultListUsersOp,
			ResourceID:     resource.Id.Resource,
		})
		bag.Push(pagination.PageState{
			ResourceTypeID: vaultListGroupsOp,
			ResourceID:     resource.Id.Resource,
		})
	}

	account, err := g.cli.GetAccount(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	switch bag.Current().ResourceTypeID {
	case vaultListUsersOp:
		bag.Pop()
		vaultMembers, err := g.cli.ListVaultMembers(ctx, resource.Id.Resource)
		if err != nil {
			return nil, "", nil, err
		}

		for _, member := range vaultMembers {
			memberCopy := member
			ur, err := userResource(memberCopy, resource.Id)
			if err != nil {
				return nil, "", nil, err
			}

			membershipGrant := grant.NewGrant(resource, memberEntitlement, ur.Id)
			if g.limitVaultPermissions != nil {
				if g.limitVaultPermissions.Contains(memberEntitlement) {
					rv = append(rv, membershipGrant)
				}
			} else {
				rv = append(rv, membershipGrant)
			}

			for _, permission := range member.Permissions {
				if g.limitVaultPermissions != nil {
					if !g.limitVaultPermissions.Contains(permission) {
						continue
					}
				}

				var userPermissionGrant *v2.Grant
				if account.Type == businessAccountType {
					userPermissionGrant = grant.NewGrant(resource, businessPermissions[permission], ur.Id)
				} else {
					userPermissionGrant = grant.NewGrant(resource, basicPermissions[permission], ur.Id)
				}
				rv = append(rv, userPermissionGrant)
			}
		}
	case vaultListGroupsOp:
		bag.Pop()
		vaultGroups, err := g.cli.ListVaultGroups(ctx, resource.Id.Resource)
		if err != nil {
			return nil, "", nil, err
		}

		for _, group := range vaultGroups {
			groupCopy := group
			rid := &v2.ResourceId{
				Resource:     groupCopy.ID,
				ResourceType: resourceTypeGroup.Id,
			}

			membershipGrant := grant.NewGrant(resource, memberEntitlement, rid,
				grant.WithAnnotation(&v2.GrantExpandable{
					EntitlementIds: []string{
						fmt.Sprintf("group:%s:member", groupCopy.ID),
					},
					Shallow:         true,
					ResourceTypeIds: []string{resourceTypeUser.Id},
				}),
			)
			if g.limitVaultPermissions != nil {
				if g.limitVaultPermissions.Contains(memberEntitlement) {
					rv = append(rv, membershipGrant)
				}
			} else {
				rv = append(rv, membershipGrant)
			}

			// add group permissions to all users in the group.
			for _, permission := range group.Permissions {
				if g.limitVaultPermissions != nil {
					if !g.limitVaultPermissions.Contains(permission) {
						continue
					}
				}

				var perm string
				if account.Type == businessAccountType {
					perm = businessPermissions[permission]
				} else {
					perm = basicPermissions[permission]
				}

				groupPermissionGrant := grant.NewGrant(resource, perm, rid,
					grant.WithAnnotation(&v2.GrantExpandable{
						EntitlementIds: []string{
							fmt.Sprintf("group:%s:member", groupCopy.ID),
						},
						Shallow:         true,
						ResourceTypeIds: []string{resourceTypeUser.Id},
					}),
				)
				rv = append(rv, groupPermissionGrant)
			}
		}
	default:
		ctxzap.Extract(ctx).Warn("unexpected resource type while listing vault grants", zap.String("resource_type", bag.Current().ResourceTypeID))
		return nil, "", nil, errors.New("unexpected resource type")
	}

	npt, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, npt, nil, nil
}

// Grant a user access to a vault.
// grants to vaults must be granted and revoked from individual users only when using just-in-time provisioning.
// See Revoke limitations for more details.
// If the connector is used through a service account, it can only grant or revoke permissions on those stores that have been created from that service account, otherwise it will return an error.
func (g *vaultResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	username := principal.DisplayName
	vaultId := entitlement.Resource.Id.Resource

	permissionGrant, err := extractRoleFromEntitlementID(entitlement.Id)
	if err != nil {
		return nil, fmt.Errorf("could not extract role: %w", err)
	}

	account, err := g.cli.GetAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not fetch account: %w", err)
	}

	permissionsList := getPermissionsForGrantRevoke(permissionGrant, account.Type, false)

	permissions := strings.Join(permissionsList, ",")

	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		return nil, fmt.Errorf("baton-1password: only users or groups can be granted vault access")
	}

	err = g.cli.AddUserToVault(ctx, vaultId, username, permissions)
	if err != nil {
		return nil, fmt.Errorf("baton-1password: failed granting to vault access: %w", err)
	}

	return nil, nil
}

// Revoke a user's access to a vault.
// This will error out if the principal's grant was inherited via a group membership with permissions to the vault.
// 1Password CLI errors with "the accessor doesn't have any permissions" if the grant is inherited from a group.
// Avoid mixing group and individual grants to vaults when using just-in-time provisioning.
// If the connector is used through a service account, it can only grant or revoke permissions on those stores that have been created from that service account, otherwise it will return an error.
func (g *vaultResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	entitlement := grant.Entitlement

	permissionGrant, err := extractRoleFromEntitlementID(entitlement.Id)
	if err != nil {
		return nil, fmt.Errorf("could not extract role: %w", err)
	}

	account, err := g.cli.GetAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not fetch account: %w", err)
	}

	permissionsList := getPermissionsForGrantRevoke(permissionGrant, account.Type, true)

	permissions := strings.Join(permissionsList, ",")

	principal := grant.Principal
	username := principal.DisplayName
	vaultId := entitlement.Resource.Id.Resource

	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, errors.New("baton-1password: only users can have vault access revoked")
	}

	err = g.cli.RemoveUserFromVault(ctx, vaultId, username, permissions)
	if err != nil {
		return nil, fmt.Errorf("baton-1password: failed removing user from vault: %w", err)
	}

	return nil, nil
}

func vaultBuilder(cli *onepassword.OnePasswordClient, limitVaultPermissions mapset.Set[string]) *vaultResourceType {
	return &vaultResourceType{
		resourceType:          resourceTypeVault,
		cli:                   cli,
		limitVaultPermissions: limitVaultPermissions,
	}
}
