package connector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddPermissionDeps(t *testing.T) {
	perms := addPermissionDeps("create_items")
	require.Equal(t, "create_items,view_items", perms)
	perms = addPermissionDeps("view_items")
	require.Equal(t, "view_items", perms)
	perms = addPermissionDeps("")
	require.Equal(t, "", perms)
}
