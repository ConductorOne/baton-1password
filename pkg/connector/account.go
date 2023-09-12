package connector

import (
	"context"

	onepassword "github.com/conductorone/baton-1password/pkg/1password"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type accountResourceType struct {
	resourceType *v2.ResourceType
	cli          *onepassword.Cli
}

func (a *accountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return a.resourceType
}

// Create a new connector resource for a 1Password account.
func accountResource(account onepassword.Account) (*v2.Resource, error) {
	ret, err := resource.NewResource(
		account.Name,
		resourceTypeAccount,
		account.ID,
		resource.WithAnnotation(
			&v2.ChildResourceType{ResourceTypeId: resourceTypeGroup.Id},
			&v2.ChildResourceType{ResourceTypeId: resourceTypeUser.Id},
			&v2.ChildResourceType{ResourceTypeId: resourceTypeVault.Id},
		),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (a *accountResourceType) List(_ context.Context, _ *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource

	account, err := a.cli.GetAccount()
	if err != nil {
		return nil, "", nil, err
	}

	ar, err := accountResource(account)
	if err != nil {
		return nil, "", nil, err
	}

	rv = append(rv, ar)

	return rv, "", nil, nil
}

func (a *accountResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	memberOptions := PopulateOptions(resource.DisplayName, memberEntitlement, resource.Id.ResourceType)
	memberEntitlement := ent.NewAssignmentEntitlement(resource, memberEntitlement, memberOptions...)
	rv = append(rv, memberEntitlement)

	return rv, "", nil, nil
}

func (a *accountResourceType) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	users, err := a.cli.ListUsers()
	if err != nil {
		return nil, "", nil, err
	}

	for _, user := range users {
		userCopy := user
		ur, err := userResource(userCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}

		grant := grant.NewGrant(resource, memberEntitlement, ur.Id)
		rv = append(rv, grant)
	}

	return rv, "", nil, nil
}

func accountBuilder(cli *onepassword.Cli) *accountResourceType {
	return &accountResourceType{
		resourceType: resourceTypeAccount,
		cli:          cli,
	}
}
