package connector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveDeps(t *testing.T) {
	expected := []string{"view_items", "create_items"}
	actual := resolveDeps("create_items", dependencyMap, make(map[string]bool))
	require.Equal(t, expected, actual)

	expected = []string{"view_items", "view_and_copy_passwords", "edit_items"}
	actual = resolveDeps("edit_items", dependencyMap, make(map[string]bool))
	require.Equal(t, expected, actual)

	expected = []string{"manage_vault"}
	actual = resolveDeps("manage_vault", dependencyMap, make(map[string]bool))
	require.Equal(t, expected, actual)

	expected = []string{""}
	actual = resolveDeps("", dependencyMap, make(map[string]bool))
	require.Equal(t, expected, actual)
}
