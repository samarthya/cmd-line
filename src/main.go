// Package main defines the entry point for the application
package main

import (
	"fmt"
	"os"

	"github.com/samarthya/cmd-line/cmd"
	"github.com/spf13/cobra"
)

var (
	message string
	rootCmd = &cobra.Command{
		Use: "./vault-agent command [flags]",
	}
)

func init() {
	rootCmd.AddCommand(cmd.VaultCmd)
	rootCmd.AddCommand(cmd.HelloCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
