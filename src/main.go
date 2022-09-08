// Package main defines the entry point for the application
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const (
	// MessageFlag defines the Message to display. Default vault is Hello World!
	MessageFlag = "message"
)

var (
	message string
	rootCmd = &cobra.Command{
		Use:        "hello",
		Aliases:    []string{"echo", "msg"},
		SuggestFor: []string{"hllo", "helo", "ecoh", "message"},
		Short:      "A simple echo",
		Long:       "Allows you to validate the command output via a message returned.",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Println("Invalid usage: ")
				cmd.Help()
				os.Exit(1)
			}
			log.Printf(" Flags: %v", message)
			fmt.Printf(">> %s<<\n", message)
		},
	}
)

func init() {
	log.Println(" Initalise called!")
	// Do not want to sort
	cobra.EnableCommandSorting = false
	rootCmd.Flags().StringVarP(&message, MessageFlag, "m", "Hello World!", "Message that will be displayed")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
