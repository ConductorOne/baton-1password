package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	Address string `mapstructure:"address"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.Address == "" {
		return fmt.Errorf("sign in address is missing")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("address", "", "Sign in address of your 1Password account. ($BATON_ADDRESS)")
}
