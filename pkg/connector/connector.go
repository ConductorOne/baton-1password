package connector

import (
	"context"
	"fmt"

	onepassword "github.com/conductorone/baton-1password/pkg/1password"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	mapset "github.com/deckarep/golang-set/v2"
)

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotationsForUserResourceType(),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
	}
	resourceTypeAccount = &v2.ResourceType{
		Id:          "account",
		DisplayName: "Account",
	}
	resourceTypeVault = &v2.ResourceType{
		Id:          "vault",
		DisplayName: "Vault",
	}
)

type OnePassword struct {
	cli                   *onepassword.Cli
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
