package main

import "github.com/spf13/cobra"

// newAuthCmd returns the top-level "auth" subcommand.
// Children (passwords, …) are added in their own files.
func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication and credential management",
	}
	cmd.AddCommand(newAuthPasswordsCmd())
	return cmd
}
