package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const authTypeUser = "user"

// sessionExpiredMessages are (lowercased) substrings `op` prints to stderr
// when a --session token is stale or absent. The wording observed in
// practice depends on *how* the session is missing, confirmed against a real
// op CLI 2.42.0 failure in this connector's own deployment:
//   - "no active session found for account <name>" (exit code 1) — when a
//     --session <token> flag IS passed but the token itself is stale/invalid.
//     This is the one this connector actually hits, since runOpCommand always
//     passes --session.
//   - "you are not currently signed in...op signin --help..." (exit code 7,
//     observed on op CLI 2.x 2022-2026 per GitHub issue reports) — when no
//     --session is passed at all. Kept as a fallback in case of CLI version
//     or invocation differences.
var sessionExpiredMessages = []string{
	"no active session found",
	"you are not currently signed in",
}

type OnePasswordClient struct {
	authType string

	// tokenMu guards token and sessionBroken. Resource builders
	// (user/group/account/vault) all share one *OnePasswordClient, and the
	// SDK can run their syncs concurrently (--parallel-sync / --worker-count),
	// so a session refresh triggered by one goroutine must not race with a
	// read/write from another.
	tokenMu sync.Mutex
	token   string

	// sessionBroken trips after a re-signin attempt itself fails (as opposed
	// to the session simply expiring, which is expected and retried once).
	// 1Password doesn't publish a failed-signin lockout threshold for `op
	// signin`, so rather than guess a retry count, we stop trying entirely
	// after the first failed refresh: every subsequent call fails fast
	// without another signin attempt, bounding a single sync run to at most
	// one extra `op signin` beyond the one at startup. A fresh process (the
	// next hourly sync) gets a clean sessionBroken state and tries again.
	sessionBroken bool

	// accountDetails is only set for authType "user". It lets executeCommand
	// transparently re-run `op signin` and retry once when the cached
	// session token expires mid-sync (op user sessions expire after 30
	// minutes of inactivity, which can be shorter than a single sync run).
	accountDetails *AccountDetails
}

func NewCli(authType string, token string, accountDetails *AccountDetails) *OnePasswordClient {
	return &OnePasswordClient{
		authType:       authType,
		token:          token,
		accountDetails: accountDetails,
	}
}

func NewAccount(address string, email string, secret string, password string) *AccountDetails {
	return &AccountDetails{
		address:  address,
		email:    email,
		secret:   secret,
		password: password,
	}
}

// Get the accounts listed on the local config.
func GetLocalAccounts(ctx context.Context) ([]LocalAccountDetails, error) {
	l := ctxzap.Extract(ctx)

	var err error
	var output []byte

	cmd := exec.CommandContext(ctx, "op", "accounts", "list", "--format=json")
	if output, err = cmd.Output(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			l.Error(
				"error executing 'op accounts list' command",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
				zap.Int("exit_code", exitErr.ExitCode()),
			)
		}
		return nil, fmt.Errorf("error executing command: %w", err)
	}

	var accounts []LocalAccountDetails
	if err = json.Unmarshal(output, &accounts); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	return accounts, nil
}

// Returns the account UUID.
func GetLocalAccountUUID(ctx context.Context, email string) (string, error) {
	accounts, err := GetLocalAccounts(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting local accounts: %w", err)
	}

	for _, account := range accounts {
		if account.Email == email {
			return account.AccountUUID, nil
		}
	}

	return "", nil
}

// Adds a user account to the local config.
func AddLocalAccount(ctx context.Context, providedAccountDetails *AccountDetails) (string, error) {
	l := ctxzap.Extract(ctx)

	var (
		err     error
		addIn   io.WriteCloser
		account string
	)

	// Must be provided as environment variable
	if err := os.Setenv("OP_SECRET_KEY", providedAccountDetails.secret); err != nil {
		return "", err
	}

	args := []string{"account", "add", "--address", providedAccountDetails.address, "--email", providedAccountDetails.email, "--raw"}

	addCmd := exec.CommandContext(ctx, "op", args...)
	if addIn, err = addCmd.StdinPipe(); err != nil {
		return "", err
	}

	if err = addCmd.Start(); err != nil {
		return "", err
	}

	if _, err = fmt.Fprintf(addIn, "%s\n", providedAccountDetails.password); err != nil {
		return "", err
	}

	if err = addIn.Close(); err != nil {
		return "", err
	}

	if err = addCmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			l.Error(
				"error executing 'op account add' command",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
				zap.Int("exit_code", exitErr.ExitCode()),
			)
		}
		return "", fmt.Errorf("error starting command: %w", err)
	}

	if account, err = GetLocalAccountUUID(ctx, providedAccountDetails.email); err != nil {
		return "", fmt.Errorf("error getting accountuuid after account add: %w", err)
	}

	l.Debug(fmt.Sprintf("Local account added: %s", account))

	return account, nil
}

func GetUserToken(ctx context.Context, providedAccountDetails *AccountDetails) (string, error) {
	l := ctxzap.Extract(ctx)

	var (
		err error
	)

	if providedAccountDetails.password == "" {
		l.Error("password must be provided")
		return "", fmt.Errorf("password is required for user auth-type")
	}

	account, err := GetLocalAccountUUID(ctx, providedAccountDetails.email)
	if err != nil {
		l.Error("failed to check local accounts: ", zap.Error(err))
		return "", err
	}

	if account == "" {
		if account, err = AddLocalAccount(ctx,
			providedAccountDetails,
		); err != nil {
			l.Error("failed to add local account: ", zap.Error(err))
			return "", err
		}
	}

	token, err := SignIn(ctx,
		account,
		providedAccountDetails,
	)

	if err != nil {
		l.Error("failed to SignIn: ", zap.Error(err))
		return "", err
	}

	return token, nil
}

// Sign in to 1Password, returning the token.
// If password is not provided, user will be prompted for it.
func SignIn(ctx context.Context, account string, providedAccountDetails *AccountDetails) (string, error) {
	l := ctxzap.Extract(ctx)

	var (
		out    bytes.Buffer
		stderr bytes.Buffer
		err    error
		pipeIn io.WriteCloser
	)

	cmd := exec.CommandContext(ctx, "op", "signin", "--account", account, "--raw")

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if pipeIn, err = cmd.StdinPipe(); err != nil {
		return "", err
	}

	if _, err = fmt.Fprintf(pipeIn, "%s\n", providedAccountDetails.password); err != nil {
		return "", err
	}

	if err = pipeIn.Close(); err != nil {
		return "", err
	}

	if err = cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			l.Error(
				"error executing 'op signin --raw' command",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
				zap.Int("exit_code", exitErr.ExitCode()),
			)
		}
		return "", fmt.Errorf("error executing command: %w", err)
	}

	l.Debug("SignIn Completed")

	return out.String(), nil
}

// GetSignedInAccount gets information about the signed in account.
func (c *OnePasswordClient) GetSignedInAccount(ctx context.Context) (AuthResponse, error) {
	args := []string{"whoami"}

	var res AuthResponse
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error getting signed in account details: %w", err)
	}

	return res, nil
}

// GetAccount gets information about the account.
func (c *OnePasswordClient) GetAccount(ctx context.Context) (Account, error) {
	args := []string{"account", "get"}

	var res Account
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return Account{}, fmt.Errorf("error getting account: %w", err)
	}

	return res, nil
}

// ListUsers lists all users in the account.
func (c *OnePasswordClient) ListUsers(ctx context.Context) ([]User, error) {
	args := []string{"user", "list"}

	var res []User
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing users: %w", err)
	}

	return res, nil
}

// ListGroups lists all groups in the account.
func (c *OnePasswordClient) ListGroups(ctx context.Context) ([]Group, error) {
	args := []string{"group", "list"}

	var res []Group
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing groups: %w", err)
	}

	return res, nil
}

// ListGroupMembers lists all members of a group.
func (c *OnePasswordClient) ListGroupMembers(ctx context.Context, group string) ([]User, error) {
	args := []string{"group", "user", "list", group}

	var res []User
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing group members: %w", err)
	}

	return res, nil
}

// ListVaults lists all vaults in the account.
func (c *OnePasswordClient) ListVaults(ctx context.Context) ([]Vault, error) {
	args := []string{"vault", "list"}

	var res []Vault
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vaults: %w", err)
	}

	return res, nil
}

// ListVaultGroups lists all groups that have access to a vault.
func (c *OnePasswordClient) ListVaultGroups(ctx context.Context, vaultId string) ([]Group, error) {
	args := []string{"vault", "group", "list", vaultId}

	var res []Group
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vault groups: %w", err)
	}

	return res, nil
}

// ListVaultMembers lists all users that have access to a vault.
func (c *OnePasswordClient) ListVaultMembers(ctx context.Context, vaultId string) ([]User, error) {
	args := []string{"vault", "user", "list", vaultId}

	var res []User
	err := c.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vault members: %w", err)
	}

	return res, nil
}

// AddUserToGroup adds user to group.
func (c *OnePasswordClient) AddUserToGroup(ctx context.Context, group, role, user string) error {
	args := []string{"group", "user", "grant", "--group", group, "--role", role, "--user", user}

	err := c.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error adding user as a member: %w", err)
	}

	// role can either member or manager but in order for user to be a manager the member role needs to be assigned first.
	// so we execute the command once more in order for member to become a manager.
	if role == "manager" {
		err := c.executeCommand(ctx, args, nil)
		if err != nil {
			return fmt.Errorf("error adding user as a manager: %w", err)
		}
	}

	return nil
}

// RemoveUserFromGroup removes user from group.
func (c *OnePasswordClient) RemoveUserFromGroup(ctx context.Context, group, user string) error {
	args := []string{"group", "user", "revoke", "--group", group, "--user", user}

	err := c.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error removing user from group: %w", err)
	}

	return nil
}

// AddUserToVault adds user to vault.
func (c *OnePasswordClient) AddUserToVault(ctx context.Context, vault, user, permissions string) error {
	args := []string{"vault", "user", "grant", "--vault", vault, "--user", user, "--permissions", permissions}

	err := c.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error adding user to vault: %w", err)
	}

	return nil
}

// RemoveUserFromVault removes user from vault.
// This will error out if the principal's grant was inherited via a group membership with permissions to the vault.
// 1Password CLI errors with "the accessor doesn't have any permissions" if the grant is inherited from a group.
// Avoid mixing group and individual grants to vaults when using just-in-time provisioning.
func (c *OnePasswordClient) RemoveUserFromVault(ctx context.Context, vault, user, permissions string) error {
	args := []string{"vault", "user", "revoke", "--vault", vault, "--user", user, "--permissions", permissions}

	err := c.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error removing user from vault: %w", err)
	}

	return nil
}

// currentToken returns the session token under lock, so concurrent syncs of
// different resource types never read a token mid-write by a refresh.
func (c *OnePasswordClient) currentToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.token
}

// redactSessionToken returns args with any value following "--session"
// masked, for safe inclusion in logs. The session token is a bearer
// credential and must never be written out in full.
func redactSessionToken(args []string) []string {
	redacted := make([]string, len(args))
	copy(redacted, args)
	for i, a := range redacted {
		if a == "--session" && i+1 < len(redacted) {
			redacted[i+1] = "REDACTED" // matches the convention used by baton-sdk's uhttp.RedactSensitiveHeaders
		}
	}
	return redacted
}

// runOpCommand runs op with args. For user auth, token is passed as
// --session; callers pass the token explicitly (rather than reading it here)
// so that on failure they know exactly which token the command used.
func (c *OnePasswordClient) runOpCommand(ctx context.Context, args []string, token string) ([]byte, error) {
	l := ctxzap.Extract(ctx)

	cmdArgs := make([]string, 0, len(args)+3)
	cmdArgs = append(cmdArgs, args...)

	if c.authType == authTypeUser {
		cmdArgs = append(cmdArgs, "--session", token)
	}
	cmdArgs = append(cmdArgs, "--format=json")

	cmd := exec.CommandContext(ctx, "op", cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// A stale session is expected and handled by executeCommand (which
			// logs a Warn and re-signs in), so don't log it at Error here.
			logFn := l.Error
			if isSessionExpiredError(err) {
				logFn = l.Debug
			}
			logFn(
				"error executing command",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
				zap.String("stdout", string(output)),
				zap.Int("exit_code", exitErr.ExitCode()),
				zap.Strings("command_args", redactSessionToken(cmd.Args)),
			)
		}

		return output, err
	}

	return output, nil
}

// isSessionExpiredError reports whether err is an `op` exit error caused by a
// stale or missing --session token, as opposed to any other failure (bad
// args, network error, permission denial, etc).
func isSessionExpiredError(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}

	stderr := strings.ToLower(string(exitErr.Stderr))
	for _, msg := range sessionExpiredMessages {
		if strings.Contains(stderr, msg) {
			return true
		}
	}

	return false
}

// sessionRefreshBroken reports whether a prior refresh attempt already
// failed this run, so callers can fail fast instead of signing in again.
func (c *OnePasswordClient) sessionRefreshBroken() bool {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.sessionBroken
}

// refreshStaleSession re-authenticates if the live token still matches
// staleToken. If another goroutine already refreshed it first (possible
// under --parallel-sync, since all resource builders share one client), this
// is a no-op and the caller retries with the already-fresh token.
//
// A failed refresh permanently trips sessionBroken for this client: 1Password
// publishes no failed-signin lockout threshold for `op signin`, so rather
// than guess how many retries are safe, a single failure here stops all
// further signin attempts for the rest of this process's life.
func (c *OnePasswordClient) refreshStaleSession(ctx context.Context, staleToken string) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.sessionBroken {
		return fmt.Errorf("op session refresh previously failed this run; not retrying signin")
	}

	if c.token != staleToken {
		return nil
	}

	token, err := GetUserToken(ctx, c.accountDetails)
	if err != nil {
		c.sessionBroken = true
		return err
	}

	c.token = token
	return nil
}

func (c *OnePasswordClient) executeCommand(ctx context.Context, args []string, res interface{}) error {
	l := ctxzap.Extract(ctx)

	if c.authType == authTypeUser && c.sessionRefreshBroken() {
		return fmt.Errorf("error: op session refresh already failed once this run; aborting sync instead of retrying signin again (command: %v)", redactSessionToken(args))
	}

	// Capture the token before running the command: if it fails as stale,
	// this is the token to compare against in refreshStaleSession. Reading it
	// after the failure could pick up a token another goroutine already
	// refreshed, triggering a redundant signin.
	usedToken := c.currentToken()
	output, err := c.runOpCommand(ctx, args, usedToken)
	if err != nil && c.authType == authTypeUser && c.accountDetails != nil && isSessionExpiredError(err) {
		l.Warn("op session expired mid-sync, re-authenticating and retrying", zap.Strings("command_args", redactSessionToken(args)))

		// GetUserToken/SignIn already log the signin failure, so it is not logged again here.
		if signInErr := c.refreshStaleSession(ctx, usedToken); signInErr != nil {
			return fmt.Errorf("error: %w (session refresh failed: %w)", err, signInErr)
		}

		output, err = c.runOpCommand(ctx, args, c.currentToken())
	}
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	if res == nil {
		return nil
	}

	if err := json.Unmarshal(output, &res); err != nil {
		return fmt.Errorf("error unmarshalling response: %w", err)
	}

	return nil
}
