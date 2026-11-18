package onepassword

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	staleSessionErr := runShellForExitError(t,
		`echo "Using configuration at non-standard location \"/tmp/.op-config\"" >&2; `+
			`echo "[ERROR] 2026/11/06 16:54:30 no active session found for account my" >&2; exit 1`)
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
	c := NewCli(authTypeUser, "initial-token", &AccountDetails{})

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
	c := NewCli(authTypeUser, "token", &AccountDetails{})
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
	c := NewCli(authTypeUser, "some-token", &AccountDetails{})

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

// stubOp is a fake `op` binary for exercising the session-refresh path
// end to end. State lives in $OP_STUB_DIR:
//   - valid:       the only session token commands accept
//   - signins:     one line appended per `op signin` call
//   - fail_signin: if present, `op signin` fails
const stubOp = `#!/bin/sh
dir="$OP_STUB_DIR"
case "$1" in
accounts)
	echo '[{"email":"me@example.com","account_uuid":"ACC"}]'
	exit 0
	;;
signin)
	cat >/dev/null
	echo x >> "$dir/signins"
	if [ -f "$dir/fail_signin" ]; then
		echo "[ERROR] signin failed" >&2
		exit 1
	fi
	tok="token-$(wc -l < "$dir/signins" | tr -d ' ')"
	printf '%s' "$tok" > "$dir/valid"
	echo "$tok"
	exit 0
	;;
esac
prev=""
sess=""
for a in "$@"; do
	if [ "$prev" = "--session" ]; then sess="$(printf '%s' "$a")"; fi
	prev="$a"
done
if [ "$sess" != "$(cat "$dir/valid")" ]; then
	echo "[ERROR] no active session found for account my" >&2
	exit 1
fi
echo '[]'
`

// setupStubOp puts stubOp first on PATH with the given currently-valid
// session token, and returns the stub's state dir.
func setupStubOp(t *testing.T, validToken string) string {
	t.Helper()

	binDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "op"), []byte(stubOp), 0o700)) //nolint:gosec // test stub must be executable

	stateDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "valid"), []byte(validToken), 0o600))

	t.Setenv("OP_STUB_DIR", stateDir)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return stateDir
}

func signinCount(t *testing.T, stateDir string) int {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(stateDir, "signins"))
	if os.IsNotExist(err) {
		return 0
	}
	require.NoError(t, err)

	return strings.Count(string(b), "\n")
}

func newStubUserClient(token string) *OnePasswordClient {
	return NewCli(authTypeUser, token, NewAccount("my.1password.com", "me@example.com", "secret", "password"))
}

func TestExecuteCommand_RefreshesExpiredSessionAndRetries(t *testing.T) {
	stateDir := setupStubOp(t, "server-side-token")
	c := newStubUserClient("expired-token")

	var res []any
	err := c.executeCommand(context.Background(), []string{"vault", "list"}, &res)

	require.NoError(t, err)
	require.Equal(t, 1, signinCount(t, stateDir))
	require.Equal(t, "token-1", strings.TrimSpace(c.currentToken()))
	require.False(t, c.sessionRefreshBroken())
}

// TestExecuteCommand_ConcurrentExpiryRefreshesOnce checks that when many
// concurrent syncs all hit the same expired token, only one of them signs in
// again; the rest retry with the token it obtained.
func TestExecuteCommand_ConcurrentExpiryRefreshesOnce(t *testing.T) {
	stateDir := setupStubOp(t, "server-side-token")
	c := newStubUserClient("expired-token")

	const workers = 20
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = c.executeCommand(context.Background(), []string{"vault", "list"}, nil)
		}()
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, signinCount(t, stateDir))
}

func TestExecuteCommand_FailedRefreshTripsBreaker(t *testing.T) {
	stateDir := setupStubOp(t, "server-side-token")
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "fail_signin"), nil, 0o600))
	c := newStubUserClient("expired-token")

	err := c.executeCommand(context.Background(), []string{"vault", "list"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "session refresh failed")
	require.True(t, c.sessionRefreshBroken())

	err = c.executeCommand(context.Background(), []string{"vault", "list"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "aborting sync instead of retrying signin again")
	require.Equal(t, 1, signinCount(t, stateDir), "no further signin attempts after the breaker trips")
}
