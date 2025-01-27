package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	onepassword "github.com/conductorone/baton-1password/pkg/1password"
	config2 "github.com/conductorone/baton-1password/pkg/config"
	"github.com/conductorone/baton-1password/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/term"
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
		err          error
		bytePassword []byte
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

	if v.GetString(config2.PasswordField.FieldName) == "" {
		if _, err = os.Stdout.Write([]byte("Enter your password: ")); err != nil {
			l.Error("failed to prompt user for password: ", zap.Error(err))
		}
		if bytePassword, err = term.ReadPassword(syscall.Stdin); err != nil {
			l.Error("failed to read user password input: ", zap.Error(err))
		}

		os.Setenv("BATON_PASSWORD", string(bytePassword))
	}

	account, err := onepassword.GetLocalAccountUUID(ctx, v.GetString(config2.EmailField.FieldName))
	if err != nil {
		l.Error("failed to check local accounts: ", zap.Error(err))
		return nil, err
	}

	if account == "" {
		if account, err = onepassword.AddLocalAccount(ctx,
			v.GetString(config2.AddressField.FieldName),
			v.GetString(config2.EmailField.FieldName),
			v.GetString(config2.KeyField.FieldName),
			v.GetString(config2.PasswordField.FieldName),
		); err != nil {
			l.Error("failed to add local account: ", zap.Error(err))
		}
	}

	token, err := onepassword.SignIn(ctx,
		account,
		v.GetString(config2.EmailField.FieldName),
		v.GetString(config2.PasswordField.FieldName),
	)

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
