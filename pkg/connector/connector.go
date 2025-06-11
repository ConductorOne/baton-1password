package connector

import (
	"context"
	"fmt"

	onepassword "github.com/conductorone/baton-1password/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	mapset "github.com/deckarep/golang-set/v2"
)

type OnePassword struct {
	cli                   *onepassword.OnePasswordClient
	accountDetails        *onepassword.AccountDetails
	limitVaultPermissions mapset.Set[string]
}

func New(ctx context.Context, authType string, token string, providedAccountDetails *onepassword.AccountDetails, limitVaultPermissions []string) (*OnePassword, error) {
	op := &OnePassword{
		cli:            onepassword.NewCli(authType, token),
		accountDetails: providedAccountDetails,
	}
	if len(limitVaultPermissions) > 0 {
		op.limitVaultPermissions = mapset.NewSet(limitVaultPermissions...)
	}
	return op, nil
}

func (op *OnePassword) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "1Password",
		Description: "Connector that syncs users, groups, accounts, vaults and permissions from 1Password to Baton.",
	}, nil
}

func (op *OnePassword) Validate(ctx context.Context) (annotations.Annotations, error) {
	_, err := op.cli.GetSignedInAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("op-connector: failed to get signed in account: %w", err)
	}
	return nil, nil
}

func (op *OnePassword) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(op.cli),
		groupBuilder(op.cli),
		accountBuilder(op.cli),
		vaultBuilder(op.cli, op.limitVaultPermissions),
	}
}
