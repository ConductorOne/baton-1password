package main

import (
	"context"
	"fmt"
	"os"

	onepassword "github.com/conductorone/baton-1password/pkg/1password"
	config2 "github.com/conductorone/baton-1password/pkg/config"
	"github.com/conductorone/baton-1password/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	connectorName = "baton-1password"
	version       = "dev"
)

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		connectorName,
		getConnector,
		config2.ConfigurationSchema,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	limitVaultPerms := v.GetStringSlice(config2.LimitVaultPermissionsField.FieldName)

	var (
		err   error
		token string
	)

	if len(limitVaultPerms) > 0 {
		validPerms := connector.AllVaultPermissions()
		for _, perm := range limitVaultPerms {
			if !validPerms.Contains(perm) {
				l.Error("invalid vault permission", zap.String("permission", perm))
				return nil, fmt.Errorf("invalid vault permission: %s", perm)
			}
		}
	}

	providedAccountDetails := onepassword.NewAccount(
		v.GetString(config2.AddressField.FieldName),
		v.GetString(config2.EmailField.FieldName),
		v.GetString(config2.KeyField.FieldName),
		v.GetString(config2.PasswordField.FieldName),
	)

	authType := v.GetString(config2.AuthTypeField.FieldName)

	switch authType {
	case "service":
		if os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") == "" {
			l.Error("environment variable OP_SERVICE_ACCOUNT_TOKEN missing")
			return nil, fmt.Errorf("service account authentication requested, but required environment variable OP_SERVICE_ACCOUNT_TOKEN is missing")
		}
	case "user":
		if token, err = onepassword.GetUserToken(
			ctx,
			providedAccountDetails,
		); err != nil {
			l.Error("unable to get token", zap.Error(err))
			return nil, err
		}
	default:
		l.Error(fmt.Sprintf("authType provided ('%s') is not handled", authType))
		return nil, fmt.Errorf("authType provided ('%s') is not handled", authType)
	}

	cb, err := connector.New(
		ctx,
		authType,
		token,
		providedAccountDetails,
		limitVaultPerms,
	)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}
	return connector, nil
}
