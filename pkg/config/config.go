package config

import (
	"slices"
	"strings"

	"github.com/conductorone/baton-1password/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/field"
)

func sortedVaultPermissions() []string {
	perms := connector.AllVaultPermissions().ToSlice()
	slices.Sort(perms)
	return perms
}

var (
	AddressField = field.StringField(
		"address",
		field.WithDescription("Sign in address of your 1Password account"),
		field.WithRequired(true),
	)

	LimitVaultPermissionsField = field.StringSliceField(
		"limit-vault-permissions",
		field.WithDescription("Limit ingested vault permissions: "+strings.Join(sortedVaultPermissions(), ", ")),
		field.WithRequired(false),
	)

	ConfigurationFields = []field.SchemaField{
		AddressField,
		LimitVaultPermissionsField,
	}

	FieldRelationships = []field.SchemaFieldRelationship{}

	ConfigurationSchema = field.Configuration{
		Fields: ConfigurationFields,
	}
)
