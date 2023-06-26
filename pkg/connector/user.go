package connector

import (
	"context"
	"strings"

	onepassword "github.com/ConductorOne/baton-1password/pkg/1password"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	resource "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userResourceType struct {
	resourceType *v2.ResourceType
	cli          *onepassword.Cli
}

func (u *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return u.resourceType
}

// Create a new connector resource for a 1Password user.
func userResource(user onepassword.User, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	names := strings.SplitN(user.Name, " ", 2)
	var firstName, lastName string
	switch len(names) {
	case 1:
		firstName = names[0]
	case 2:
		firstName = names[0]
		lastName = names[1]
	}

	profile := map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"login":      user.Email,
		"user_id":    user.ID,
	}

	var userStatus v2.UserTrait_Status_Status

	switch user.State {
	case "INACTIVE":
		userStatus = v2.UserTrait_Status_STATUS_DISABLED
	case "ACTIVE":
		userStatus = v2.UserTrait_Status_STATUS_ENABLED
	default:
		userStatus = v2.UserTrait_Status_STATUS_UNSPECIFIED
	}

	userTraitOptions := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
		resource.WithStatus(userStatus),
		resource.WithEmail(user.Email, true),
	}

	ret, err := resource.NewUserResource(
		user.Name,
		resourceTypeUser,
		user.ID,
		userTraitOptions,
		resource.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (u *userResourceType) List(_ context.Context, parentId *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentId == nil {
		return nil, "", nil, nil
	}

	var rv []*v2.Resource

	users, err := u.cli.ListUsers()
	if err != nil {
		return nil, "", nil, err
	}

	for _, user := range users {
		userCopy := user
		ur, err := userResource(userCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	return rv, "", nil, nil
}

func (u *userResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (u *userResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userBuilder(cli *onepassword.Cli) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		cli:          cli,
	}
}
