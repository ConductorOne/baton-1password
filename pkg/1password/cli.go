package onepassword

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
func SignIn(account string) (string, error) {
	cmd := exec.Command("op", "signin", "--account", account, "--raw")
	out := bytes.NewBuffer(nil)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error starting command: %w", err)
	}

	return out.String(), nil
}

// GetSignedInAccount gets information about the signed in account.
func (cli *Cli) GetSignedInAccount() (AuthResponse, error) {
	args := []string{"whoami"}

	var res AuthResponse
	err := cli.executeCommand(args, &res)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("error getting signed in account details: %w", err)
	}

	return res, nil
}

// GetAccount gets information about the account.
func (cli *Cli) GetAccount() (Account, error) {
	args := []string{"account", "get"}

	var res Account
	err := cli.executeCommand(args, &res)
	if err != nil {
		return Account{}, fmt.Errorf("error getting account: %w", err)
	}

	return res, nil
}

// ListUsers lists all users in the account.
func (cli *Cli) ListUsers() ([]User, error) {
	args := []string{"user", "list"}

	var res []User
	err := cli.executeCommand(args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing users: %w", err)
	}

	return res, nil
}

// ListGroups lists all groups in the account.
func (cli *Cli) ListGroups() ([]Group, error) {
	args := []string{"group", "list"}

	var res []Group
	err := cli.executeCommand(args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing groups: %w", err)
	}

	return res, nil
}

// ListGroupMembers lists all members of a group.
func (cli *Cli) ListGroupMembers(group string) ([]User, error) {
	args := []string{"group", "user", "list", group}

	var res []User
	err := cli.executeCommand(args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing group members: %w", err)
	}

	return res, nil
}

// ListVaults lists all vaults in the account.
func (cli *Cli) ListVaults() ([]Vault, error) {
	args := []string{"vault", "list"}

	var res []Vault
	err := cli.executeCommand(args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vaults: %w", err)
	}

	return res, nil
}

// ListVaultGroups lists all groups that have access to a vault.
func (cli *Cli) ListVaultGroups(vaultId string) ([]Group, error) {
	args := []string{"vault", "group", "list", vaultId}

	var res []Group
	err := cli.executeCommand(args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vault groups: %w", err)
	}

	return res, nil
}

// ListVaultMembers lists all users that have access to a vault.
func (cli *Cli) ListVaultMembers(vaultId string) ([]User, error) {
	args := []string{"vault", "user", "list", vaultId}

	var res []User
	err := cli.executeCommand(args, &res)
	if err != nil {
		return nil, fmt.Errorf("error listing vault members: %w", err)
	}

	return res, nil
}

// AddUserToGroup adds user to group.
func (cli *Cli) AddUserToGroup(group, role, user string) error {
	args := []string{"group", "user", "grant", "--group", group, "--role", role, "--user", user}

	err := cli.executeCommand(args, nil)
	if err != nil {
		return fmt.Errorf("error adding user as a member: %w", err)
	}

	// role can either member or manager but in order for user to be a manager the member role needs to be assigned first.
	// so we execute the command once more in order for member to become a manager.
	if role == "manager" {
		err := cli.executeCommand(args, nil)
		if err != nil {
			return fmt.Errorf("error adding user as a manager: %w", err)
		}
	}

	return nil
}

// RemoveUserFromGroup removes user from group.
func (cli *Cli) RemoveUserFromGroup(group, user string) error {
	args := []string{"group", "user", "revoke", "--group", group, "--user", user}

	err := cli.executeCommand(args, nil)
	if err != nil {
		return fmt.Errorf("error removing user from group: %w", err)
	}

	return nil
}

func (cli *Cli) executeCommand(args []string, res interface{}) error {
	defaultArgs := []string{"--format=json", "--session", cli.token}
	defaultArgs = append(args, defaultArgs...)

	cmd := exec.Command("op", defaultArgs...) // #nosec
	output, err := cmd.Output()
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
