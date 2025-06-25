# baton-1password

`baton-1password` is a connector for 1Password built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the 1Password CLI tool to sync data about account, users, groups and vaults.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## Prerequisites

1. 1Password Families, Teams, Business or Enterprise plan (https://1password.com/business-pricing).
2. 1Password 8 app installed. Please refer to [requirements](https://developer.1password.com/docs/cli/get-started#requirements) based on your OS. 
3. Installed 1Password [CLI Tool](https://developer.1password.com/docs/cli) on your local machine. For first time install please refer to the [Install](https://developer.1password.com/docs/cli/get-started/#install) chapter. It is not neccessary to do any other steps as the `baton-1password` will take care of creating an account and signing in.
   If you already have the CLI tool installed but need to upgrade it to the latest version please refer to [this](https://developer.1password.com/docs/cli/upgrade/) article.

   IMPORTANT NOTE: If a service account is used, its token must be stored in a local environment variable (OP_SERVICE_ACCOUNT_TOKEN) in order for the 1Password CLI to authenticate properly:
```
            OP_SERVICE_ACCOUNT_TOKEN=your-service-account-token
```

## Connector capabilities

- The connector can be authenticated using either a regular user account or a 1Password service account.

- Sync Users, projects, groups and vaults.

- Supports Groups provision

- Support Vaults provision
  IMPORTANT NOTE: Vault provisioning is limited with a service account:
  When using a service account to run the connector, vault provisioning is limited by 1Password. Specifically, only vaults that were created by the same service account can be modified. 
  Vaults that were created by other users or service accounts cannot be granted or revoked permissions using a service account.

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-1password
baton-1password
baton resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-1password/cmd/baton-1password@main

BATON_ADDRESS=myaddress.1password.com baton-1password
baton resources
```

# Data Model

`baton-1password` pulls down information about the following 1password resources:

- Account
- Users
- Groups
- Vaults

# Contributing, Support, and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-1password` Command Line Usage

```
baton-1password

Usage:
  baton-1password [flags]
  baton-1password [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --address string                    Sign in address of your 1Password account. Defaults to 'my.1password.com' ($BATON_ADDRESS)
      --email string                      Email for your 1Password account. ($BATON_EMAIL)
      --secret-key string                 Secret Key for your 1Password account. ($BATON_SECRET_KEY)
      --password string                   Password for your 1Password account. ($BATON_PASSWORD) If not provided, manual input required.
      --auth-type string                  How the CLI should authenticate. Options: "user" (default) and "service". If using "service" authentication the OP_SERVICE_ACCOUNT_TOKEN environment variable must be set.
      --client-id string                  The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string              The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                       The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                              help for baton-1password
      --limit-vault-permissions strings   Limit ingested vault permissions: allow_editing, allow_managing, allow_viewing, archive_items, copy_and_share_items, create_items, delete_items, edit_items, export_items, import_items, manage_vault, member, print_items, view_and_copy_passwords, view_item_history, view_items ($BATON_LIMIT_VAULT_PERMISSIONS)
      --log-format string                 The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                  The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                      This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync                    This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --ticketing                         This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                           version for baton-1password

Use "baton-1password [command] --help" for more information about a command.
```
