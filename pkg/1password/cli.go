package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// 1Password CLI instance.
type Cli struct {
	token string
}

func NewCli(token string) *Cli {
	return &Cli{
		token: token,
	}
}

type AuthResponse struct {
	URL         string `json:"url"`
	Email       string `json:"email"`
	UserUUID    string `json:"user_uuid"`
	AccountUUID string `json:"account_uuid"`
	Shorthand   string `json:"shorthand"`
}

// Sign in to 1Password, returning the token.
// In case account doesn't exist, it will prompt for account creation and will login the user.
func SignIn(ctx context.Context, account string) (string, error) {
	l := ctxzap.Extract(ctx)

	cmd := exec.Command("op", "signin", "--account", account, "--raw")
	out := bytes.NewBuffer(nil)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			l.Error(
				"error executing command",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
				zap.Int("exit_code", exitErr.ExitCode()),
			)
		}
		return "", fmt.Errorf("error starting command: %w", err)
	}

	return out.String(), nil
}

// GetSignedInAccount gets information about the signed in account.
func (cli *Cli) GetSignedInAccount(ctx context.Context) (AuthResponse, error) {
	args := []string{"whoami"}

	var res AuthResponse
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error getting signed in account details: %w", err)
	}

	return res, nil
}

// GetAccount gets information about the account.
func (cli *Cli) GetAccount(ctx context.Context) (Account, error) {
	args := []string{"account", "get"}

	var res Account
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return Account{}, fmt.Errorf("error getting account: %w", err)
	}

	return res, nil
}

// ListUsers lists all users in the account.
func (cli *Cli) ListUsers(ctx context.Context) ([]User, error) {
	args := []string{"user", "list"}

	var res []User
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing users: %w", err)
	}

	return res, nil
}

// ListGroups lists all groups in the account.
func (cli *Cli) ListGroups(ctx context.Context) ([]Group, error) {
	args := []string{"group", "list"}

	var res []Group
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing groups: %w", err)
	}

	return res, nil
}

// ListGroupMembers lists all members of a group.
func (cli *Cli) ListGroupMembers(ctx context.Context, group string) ([]User, error) {
	args := []string{"group", "user", "list", group}

	var res []User
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing group members: %w", err)
	}

	return res, nil
}

// ListVaults lists all vaults in the account.
func (cli *Cli) ListVaults(ctx context.Context) ([]Vault, error) {
	args := []string{"vault", "list"}

	var res []Vault
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vaults: %w", err)
	}

	return res, nil
}

// ListVaultGroups lists all groups that have access to a vault.
func (cli *Cli) ListVaultGroups(ctx context.Context, vaultId string) ([]Group, error) {
	args := []string{"vault", "group", "list", vaultId}

	var res []Group
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vault groups: %w", err)
	}

	return res, nil
}

// ListVaultMembers lists all users that have access to a vault.
func (cli *Cli) ListVaultMembers(ctx context.Context, vaultId string) ([]User, error) {
	args := []string{"vault", "user", "list", vaultId}

	var res []User
	err := cli.executeCommand(ctx, args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vault members: %w", err)
	}

	return res, nil
}

// AddUserToGroup adds user to group.
func (cli *Cli) AddUserToGroup(ctx context.Context, group, role, user string) error {
	args := []string{"group", "user", "grant", "--group", group, "--role", role, "--user", user}

	err := cli.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error adding user as a member: %w", err)
	}

	// role can either member or manager but in order for user to be a manager the member role needs to be assigned first.
	// so we execute the command once more in order for member to become a manager.
	if role == "manager" {
		err := cli.executeCommand(ctx, args, nil)
		if err != nil {
			return fmt.Errorf("error adding user as a manager: %w", err)
		}
	}

	return nil
}

// RemoveUserFromGroup removes user from group.
func (cli *Cli) RemoveUserFromGroup(ctx context.Context, group, user string) error {
	args := []string{"group", "user", "revoke", "--group", group, "--user", user}

	err := cli.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error removing user from group: %w", err)
	}

	return nil
}

// AddUserToVault adds user to vault.
func (cli *Cli) AddUserToVault(ctx context.Context, vault, user, permissions string) error {
	args := []string{"vault", "user", "grant", "--vault", vault, "--user", user, "--permissions", permissions}

	err := cli.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error adding user to vault: %w", err)
	}

	return nil
}

// RemoveUserFromVault removes user from vault.
// This will error out if the principal's grant was inherited via a group membership with permissions to the vault.
// 1Password CLI errors with "the accessor doesn't have any permissions" if the grant is inherited from a group.
// Avoid mixing group and individual grants to vaults when using just-in-time provisioning.
func (cli *Cli) RemoveUserFromVault(ctx context.Context, vault, user, permissions string) error {
	args := []string{"vault", "user", "revoke", "--vault", vault, "--user", user, "--permissions", permissions}

	err := cli.executeCommand(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("error removing user from vault: %w", err)
	}

	return nil
}

func (cli *Cli) executeCommand(ctx context.Context, args []string, res interface{}) error {
	l := ctxzap.Extract(ctx)

	defaultArgs := []string{"--format=json", "--session", cli.token}
	defaultArgs = append(args, defaultArgs...)

	cmd := exec.Command("op", defaultArgs...) // #nosec
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
