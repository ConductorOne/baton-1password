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
	if len(limitVaultPerms) > 0 {
		validPerms := connector.AllVaultPermissions()
		for _, perm := range limitVaultPerms {
			if !validPerms.Contains(perm) {
				l.Error("invalid vault permission", zap.String("permission", perm))
				return nil, fmt.Errorf("invalid vault permission: %s", perm)
			}
		}
	}

	token, err := onepassword.SignIn(ctx, v.GetString(config2.AddressField.FieldName))
	if err != nil {
		l.Error("failed to login: ", zap.Error(err))
		return nil, err
	}

	cb, err := connector.New(
		ctx,
		token,
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
