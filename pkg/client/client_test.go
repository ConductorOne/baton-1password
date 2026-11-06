package onepassword

import (
	"context"
	"os/exec"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactSessionToken(t *testing.T) {
	in := []string{"vault", "list", "--session", "super-secret-token", "--format=json"}

	out := redactSessionToken(in)

	require.Equal(t, []string{"vault", "list", "--session", "REDACTED", "--format=json"}, out)
	// Original slice must be untouched.
	require.Equal(t, "super-secret-token", in[3])
}

func TestRedactSessionToken_NoSessionFlag(t *testing.T) {
	in := []string{"vault", "list", "--format=json"}

	out := redactSessionToken(in)

	require.Equal(t, in, out)
}

func TestIsSessionExpiredError(t *testing.T) {
	// The variant actually hit in practice: op CLI 2.42.0, --session <token>
	// passed but the token is stale. Reproduced from a real deployment log
	// (client.go's runOpCommand error log) after the "you are not currently
	// signed in" string alone failed to catch this and let a stale-session
	// error through uncaught.
	staleSessionErr := runShellForExitError(t, `echo "Using configuration at non-standard location \"/tmp/.op-config\"" >&2; echo "[ERROR] 2026/11/06 16:54:30 no active session found for account my" >&2; exit 1`)
	require.True(t, isSessionExpiredError(staleSessionErr))

	// The variant with no --session flag at all, per community-reported op
	// CLI 2.x behavior (kept as a fallback; this connector always passes
	// --session, so this path is not expected to be hit in practice).
	noSessionErr := runShellForExitError(t, `echo "[ERROR] 2026/11/06 12:00:00 You are not currently signed in. Please run op signin --help for instructions" >&2; exit 7`)
	require.True(t, isSessionExpiredError(noSessionErr))

	otherErr := runShellForExitError(t, `echo "[ERROR] some other failure" >&2; exit 1`)
	require.False(t, isSessionExpiredError(otherErr))

	require.False(t, isSessionExpiredError(nil))
}

// TestOnePasswordClient_ConcurrentTokenAccess exercises the same lock
// discipline executeCommand/refreshStaleSession use for c.token, under
// `go test -race`, to guard against the data race that existed before
// tokenMu was added (c.token read in runOpCommand and written on session
// refresh, with resource builders sharing one client under --parallel-sync).
func TestOnePasswordClient_ConcurrentTokenAccess(t *testing.T) {
	c := NewCli("user", "initial-token", &AccountDetails{})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = c.currentToken()
		}()
		go func(n int) {
			defer wg.Done()
			c.tokenMu.Lock()
			c.token = "refreshed-token"
			c.tokenMu.Unlock()
		}(i)
	}
	wg.Wait()

	require.Equal(t, "refreshed-token", c.currentToken())
}

func TestSessionRefreshBroken_DefaultsFalse(t *testing.T) {
	c := NewCli("user", "token", &AccountDetails{})
	require.False(t, c.sessionRefreshBroken())
}

// TestExecuteCommand_FastFailsWhenSessionBroken proves the circuit breaker:
// once a prior signin refresh has failed, executeCommand must refuse to
// attempt another signin — no op binary call, no network call, immediate
// error — rather than retrying once per API call for the rest of the sync.
// 1Password publishes no failed-signin lockout threshold to calibrate a
// retry count against, so this test pins the policy we chose instead: at
// most one failed refresh attempt per sync run.
func TestExecuteCommand_FastFailsWhenSessionBroken(t *testing.T) {
	c := NewCli("user", "some-token", &AccountDetails{})

	c.tokenMu.Lock()
	c.sessionBroken = true
	c.tokenMu.Unlock()

	err := c.executeCommand(context.Background(), []string{"vault", "list"}, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "aborting sync instead of retrying signin again")
}

// runShellForExitError runs a shell snippet guaranteed to fail and returns
// the resulting *exec.ExitError with Stderr populated, for exercising
// error-classification logic without shelling out to the real op binary.
func runShellForExitError(t *testing.T, script string) error {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), "sh", "-c", script)
	_, err := cmd.Output() // Output(), not Run(): only Output() populates ExitError.Stderr.
	require.Error(t, err)

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.NotEmpty(t, exitErr.Stderr)

	return err
}
