package main

import (
	"context"
	"fmt"
	"os"

	onepassword "github.com/conductorone/baton-1password/pkg/1password"
	"github.com/conductorone/baton-1password/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"
var sessionTempFile = "/tmp/baton-1password-session"

func main() {
	ctx := context.Background()
	cfg := &config{}
	l := ctxzap.Extract(ctx)
	cmd, err := cli.NewCmd(ctx, "baton-1password", cfg, validateConfig, getConnector)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	cmd.Version = version
	cmdFlags(cmd)
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	// remove tmp file
	e := os.Remove(sessionTempFile)
	if e != nil {
		l.Error("error removing file", zap.Error(err))
	}
}

func getConnector(ctx context.Context, cfg *config) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	// temp file for session token
	tmpToken, _ := os.ReadFile(sessionTempFile)
	if string(tmpToken) == "" {
		token, err := onepassword.SignIn(ctx, cfg.Address)
		if err != nil {
			l.Error("failed to login: ", zap.Error(err))
			return nil, err
		}
		e := os.WriteFile(sessionTempFile, []byte(token), 0600)
		if e != nil {
			l.Error("error writing file", zap.Error(e))
		}
	}

	cb, err := connector.New(ctx, string(tmpToken))
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return c, nil
}
