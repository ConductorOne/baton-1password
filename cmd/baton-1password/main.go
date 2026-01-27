package main

import (
	"context"
	"fmt"
	"os"

	onepassword "github.com/conductorone/baton-1password/pkg/client"
	config2 "github.com/conductorone/baton-1password/pkg/config"
	"github.com/conductorone/baton-1password/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	connectorName = "baton-1password"
	version       = "dev"
)

const (
	authTypeService = "service"
	authTypeUser    = "user"
)

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		connectorName,
		getConnector,
		config2.Config,
		connectorrunner.WithDefaultCapabilitiesConnectorBuilder(&connector.OnePassword{}),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	if err := validateVaultPermissions(v.GetStringSlice(config2.LimitVaultPermissionsField.FieldName), l); err != nil {
		return nil, err
	}

	authType := v.GetString(config2.AuthTypeField.FieldName)

	if err := validateConfigForAuthType(v, authType); err != nil {
		return nil, err
	}

	providedAccountDetails := onepassword.NewAccount(
		v.GetString(config2.AddressField.FieldName),
		v.GetString(config2.EmailField.FieldName),
		v.GetString(config2.KeyField.FieldName),
		v.GetString(config2.PasswordField.FieldName),
	)

	token, err := getAuthToken(ctx, authType, providedAccountDetails)
	if err != nil {
		return nil, err
	}

	cb, err := connector.New(ctx, authType, token, providedAccountDetails, v.GetStringSlice(config2.LimitVaultPermissionsField.FieldName))
	if err != nil {
		return nil, fmt.Errorf("error creating connector: %w", err)
	}

	newConnector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		return nil, fmt.Errorf("error creating connector builder: %w", err)
	}

	return newConnector, nil
}

func validateVaultPermissions(perms []string, l *zap.Logger) error {
	if len(perms) == 0 {
		return nil
	}
	validPerms := connector.AllVaultPermissions()
	for _, perm := range perms {
		if !validPerms.Contains(perm) {
			l.Error("invalid vault permission", zap.String("permission", perm))
			return fmt.Errorf("invalid vault permission: %s", perm)
		}
	}
	return nil
}

func getAuthToken(ctx context.Context, authType string, acc *onepassword.AccountDetails) (string, error) {
	switch authType {
	case authTypeService:
		return os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"), nil

	case authTypeUser:
		token, err := onepassword.GetUserToken(ctx, acc)
		if err != nil {
			return "", fmt.Errorf("unable to get user token: %w", err)
		}
		return token, nil

	default:
		return "", fmt.Errorf("authType provided ('%s') is not supported", authType)
	}
}

func validateConfigForAuthType(v *viper.Viper, authType string) error {
	switch authType {
	case authTypeUser:
		requiredFields := map[string]string{
			"address":  config2.AddressField.FieldName,
			"email":    config2.EmailField.FieldName,
			"key":      config2.KeyField.FieldName,
			"password": config2.PasswordField.FieldName,
		}
		for name, field := range requiredFields {
			val := v.GetString(field)
			if val == "" {
				err := fmt.Errorf("missing required field '%s' for auth-type 'user'", name)
				return err
			}
		}

	case authTypeService:
		token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if token == "" {
			err := fmt.Errorf("missing environment variable OP_SERVICE_ACCOUNT_TOKEN required for auth-type 'service'")
			return err
		}

	default:
		err := fmt.Errorf("unsupported auth-type: %s", authType)
		return err
	}

	return nil
}
