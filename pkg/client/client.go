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

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type OnePasswordClient struct {
	authType string
	token    string
}

func NewCli(authType string, token string) *OnePasswordClient {
	return &OnePasswordClient{
		authType: authType,
		token:    token,
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

func (c *OnePasswordClient) executeCommand(ctx context.Context, args []string, res interface{}) error {
	l := ctxzap.Extract(ctx)

	defaultArgs := []string{"--format=json"}

	if c.authType == "user" {
		args = append(args, []string{"--session", c.token}...)
	}

	defaultArgs = append(args, defaultArgs...)

	cmd := exec.CommandContext(ctx, "op", defaultArgs...) // #nosec G204
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			l.Error(
				"error executing command",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
				zap.String("stdout", string(output)),
				zap.Int("exit_code", exitErr.ExitCode()),
				zap.Strings("command_args", cmd.Args),
			)
		}

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
