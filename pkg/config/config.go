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
	EmailField = field.StringField(
		"email",
		field.WithDescription("Email of your 1password account"),
		field.WithRequired(false),
	)

	AuthTypeField = field.StringField(
		"auth-type",
		field.WithDescription("Autentication method to use limited to 'user' and 'service'. Default: 'user'"),
		field.WithRequired(false),
		field.WithDefaultValue("user"),
	)

	KeyField = field.StringField(
		"secret-key",
		field.WithDescription("Secret-key of your 1password account"),
		field.WithRequired(false),
	)

	PasswordField = field.StringField(
		"password",
		field.WithDescription("Password of your 1password account"),
		field.WithRequired(false),
	)

	AddressField = field.StringField(
		"address",
		field.WithDescription("Sign in address of your 1Password account"),
		field.WithRequired(false),
	)

	LimitVaultPermissionsField = field.StringSliceField(
		"limit-vault-permissions",
		field.WithDescription("Limit ingested vault permissions: "+strings.Join(sortedVaultPermissions(), ", ")),
		field.WithRequired(false),
	)

	ConfigurationFields = []field.SchemaField{
		AddressField,
		EmailField,
		AuthTypeField,
		KeyField,
		PasswordField,
		LimitVaultPermissionsField,
	}

	FieldRelationships = []field.SchemaFieldRelationship{}

	ConfigurationSchema = field.Configuration{
		Fields: ConfigurationFields,
	}
)
