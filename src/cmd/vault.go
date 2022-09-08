// Package cmd defines the command for interaction with Vault
package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	vaultAddress string
	dryRun       bool
	token        string
	roleName     string
	mountPath    string
	commonName   string
	ipSan        string
	dnsSan       string
	ttlHours     string
	password     string

	// Vault command to interact with the vault
	Vault = &cobra.Command{
		Use:        "vault",
		Aliases:    []string{"VAULT"},
		SuggestFor: []string{"Vault"},
		Short:      "Communicate with a vault instance & process",
		Long:       `Allows you to generate certificate based on communication with a vault instance.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Println("Invalid usage: ")
				cmd.Help()
				os.Exit(1)
			}
		},
	}
)
