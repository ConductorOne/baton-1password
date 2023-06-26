package connector

import (
	"context"

	onepassword "github.com/ConductorOne/baton-1password/pkg/1password"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type groupResourceType struct {
	resourceType *v2.ResourceType
	cli          *onepassword.Cli
}

const (
	memberEntitlement  = "member"
	managerEntitlement = "manager"
	manager            = "MANAGER"
)

func (g *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for a 1Password group.
func groupResource(group onepassword.Group, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_name": group.Name,
		"group_id":   group.ID,
	}

	groupTraitOptions := []resource.GroupTraitOption{
		resource.WithGroupProfile(profile),
	}

	ret, err := resource.NewGroupResource(
		group.Name,
		resourceTypeGroup,
		group.ID,
		groupTraitOptions,
		resource.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *groupResourceType) List(_ context.Context, parentId *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentId == nil {
		return nil, "", nil, nil
	}

	var rv []*v2.Resource

	groups, err := g.cli.ListGroups()
	if err != nil {
		return nil, "", nil, err
	}

	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(groupCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, gr)
	}

	return rv, "", nil, nil
}

func (g *groupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	memberOptions := PopulateOptions(resource.DisplayName, memberEntitlement, resource.Id.ResourceType)
	memberEntitlement := ent.NewAssignmentEntitlement(resource, memberEntitlement, memberOptions...)

	managerOptions := PopulateOptions(resource.DisplayName, managerEntitlement, resource.Id.ResourceType)
	managerEntitlement := ent.NewPermissionEntitlement(resource, managerEntitlement, managerOptions...)
	rv = append(rv, memberEntitlement, managerEntitlement)

	return rv, "", nil, nil
}

func (g *groupResourceType) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	groupMembers, err := g.cli.ListGroupMembers(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, err
	}

	for _, member := range groupMembers {
		memberCopy := member
		ur, err := userResource(memberCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}

		membershipGrant := grant.NewGrant(resource, memberEntitlement, ur.Id)
		rv = append(rv, membershipGrant)

		if memberCopy.Role == manager {
			managementGrant := grant.NewGrant(resource, managerEntitlement, ur.Id)
			rv = append(rv, managementGrant)
		}
	}

	return rv, "", nil, nil
}

func groupBuilder(cli *onepassword.Cli) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		cli:          cli,
	}
}
