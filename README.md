# baton-1password

`baton-1password` is a connector for 1Password built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the 1Password CLI tool to sync data about account, users, groups and vaults.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## Prerequisites

1. 1Password Families, Teams, Business or Enterprise plan (https://1password.com/business-pricing).
2. 1Password 8 app installed. Please refer to [requirements](https://developer.1password.com/docs/cli/get-started#requirements) based on your OS. 
3. Installed 1Password [CLI Tool](https://developer.1password.com/docs/cli) on your local machine. For first time install please refer to the [Install](https://developer.1password.com/docs/cli/get-started/#install) chapter. It is not neccessary to do any other steps as the `baton-1password` will take care of creating an account and signing in.
   If you already have the CLI tool installed but need to upgrade it to the latest version please refer to [this](https://developer.1password.com/docs/cli/upgrade/) article.

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
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --address string      Sign in address of your 1Password account. ($BATON_ADDRESS)
  -f, --file string         The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                help for baton-1password
      --log-format string   The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string    The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -v, --version             version for baton-1password

Use "baton-1password [command] --help" for more information about a command.

```
