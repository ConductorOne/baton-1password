package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	mapset "github.com/deckarep/golang-set/v2"
)

// Populate entitlement options for a 1Password resource.
func PopulateOptions(displayName, permission, resource string) []ent.EntitlementOption {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDescription(fmt.Sprintf("1Password %s %s", displayName, resource)),
		ent.WithDisplayName(fmt.Sprintf("%s %s %s", displayName, resource, permission)),
	}
	return options
}

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
}

func extractRoleFromEntitlementID(entitlementID string) (string, error) {
	parts := strings.Split(entitlementID, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid entitlement ID: %s", entitlementID)
	}
	role := parts[2]
	// Formatting to replace spaces with _
	role = strings.ReplaceAll(role, " ", "_")
	return role, nil
}

func uniqueStrings(input []string) []string {
	set := mapset.NewSet[string]()
	for _, s := range input {
		set.Add(s)
	}
	return set.ToSlice()
}

func getPermissionsForGrantRevoke(permissionGrant string, accountType string, isRevoke bool) []string {
	if isRevoke {
		return getRevokePermissions(permissionGrant, accountType)
	}
	return getGrantPermissions(permissionGrant, accountType)
}

func getRevokePermissions(permissionGrant string, accountType string) []string {
	switch permissionGrant {
	case memberEntitlement:
		if accountType == businessAccountType {
			return uniqueStrings(append(
				expandPermissionsForRevoke("view_items"),
				"manage_vault",
			))
		}
		return uniqueStrings(append(
			expandPermissionsForRevoke("allow_viewing"),
			"allow_managing",
		))

	case managerEntitlement:
		if accountType == businessAccountType {
			return []string{"manage_vault"}
		}
		return []string{"allow_managing"}

	default:
		return expandPermissionsForRevoke(permissionGrant)
	}
}

func getGrantPermissions(permissionGrant string, accountType string) []string {
	switch permissionGrant {
	case memberEntitlement:
		if accountType == businessAccountType {
			return resolveDeps("view_items", reverseDependencyMap, make(map[string]bool))
		}
		return expandPermissions("allow_editing")

	case managerEntitlement:
		if accountType == businessAccountType {
			return uniqueStrings(append(
				expandPermissions("view_items"),
				"manage_vault",
			))
		}
		return expandPermissions("allow_managing")

	default:
		return expandPermissions(permissionGrant)
	}
}
