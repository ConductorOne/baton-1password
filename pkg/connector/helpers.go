package connector

import (
	"fmt"

	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
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
