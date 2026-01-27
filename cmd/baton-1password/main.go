package main

import (
	"context"
	"fmt"
	"os"

	onepassword "github.com/conductorone/baton-1password/pkg/client"
	cfg "github.com/conductorone/baton-1password/pkg/config"
	"github.com/conductorone/baton-1password/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
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
		cfg.Config,
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

func getConnector(ctx context.Context, c *cfg.Onepassword) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	if err := validateVaultPermissions(c.LimitVaultPermissions, l); err != nil {
		return nil, err
	}

	if err := validateConfigForAuthType(c); err != nil {
		return nil, err
	}

	providedAccountDetails := onepassword.NewAccount(
		c.Address,
		c.Email,
		c.SecretKey,
		c.Password,
	)

	token, err := getAuthToken(ctx, c.AuthType, providedAccountDetails)
	if err != nil {
		return nil, err
	}

	cb, err := connector.New(ctx, c.AuthType, token, providedAccountDetails, c.LimitVaultPermissions)
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

func validateConfigForAuthType(c *cfg.Onepassword) error {
	switch c.AuthType {
	case authTypeUser:
		if c.Address == "" {
			return fmt.Errorf("missing required field 'address' for auth-type 'user'")
		}
		if c.Email == "" {
			return fmt.Errorf("missing required field 'email' for auth-type 'user'")
		}
		if c.SecretKey == "" {
			return fmt.Errorf("missing required field 'secret-key' for auth-type 'user'")
		}
		if c.Password == "" {
			return fmt.Errorf("missing required field 'password' for auth-type 'user'")
		}

	case authTypeService:
		token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if token == "" {
			return fmt.Errorf("missing environment variable OP_SERVICE_ACCOUNT_TOKEN required for auth-type 'service'")
		}

	default:
		return fmt.Errorf("unsupported auth-type: %s", c.AuthType)
	}

	return nil
}
