package connector

import (
	"context"
	"errors"
	"fmt"

	onepassword "github.com/conductorone/baton-1password/pkg/1password"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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

func (o *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"baton-1password: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-1password: only users can be granted group membership")
	}

	err := o.cli.AddUserToGroup(entitlement.Resource.Id.Resource, entitlement.Slug, principal.Id.Resource)

	if err != nil {
		return nil, fmt.Errorf("baton-1password: failed adding user to group")
	}

	return nil, nil
}

func (o *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"baton-1password: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, errors.New("baton-1password: only users can have group membership revoked")
	}

	err := o.cli.RemoveUserFromGroup(entitlement.Resource.Id.Resource, principal.Id.Resource)

	if err != nil {
		return nil, errors.New("baton-1password: failed removing user from group")
	}

	return nil, nil
}

func groupBuilder(cli *onepassword.Cli) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		cli:          cli,
	}
}
