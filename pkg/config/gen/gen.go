package main

import (
	cfg "github.com/conductorone/baton-1password/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("onepassword", cfg.Config)
}
