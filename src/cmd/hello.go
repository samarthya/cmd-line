// Package cmd defines the command for interaction with Vault
package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

const (
	// MessageFlag defines the Message to display. Default vault is Hello World!
	MessageFlag = "message"
)

var (
	message string

	//HelloCmd shows hello message
	HelloCmd = &cobra.Command{
		Use:              "hello",
		Example:          "hello -m wow!",
		Aliases:          []string{"echo", "msg"},
		SuggestFor:       []string{"hllo", "helo", "ecoh", "message"},
		Short:            "A simple echo",
		Long:             "Allows you to validate the command output via a message returned.",
		TraverseChildren: true,
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Args: ", args)
			log.Printf(" Flags: %v", message)
			fmt.Printf(">> %s <<\n", message)
		},
	}
)

func init() {
	log.Println("Hello: Initialized")
	// Do not want to sort
	// cobra.EnableCommandSorting = false
	HelloCmd.Flags().StringVarP(&message, MessageFlag, "m", "Hello World!", "Message that will be displayed")
}
