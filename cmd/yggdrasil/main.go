// Command yggdrasil is the Yggdrasil Core admin CLI.
//
// It provides subcommands for managing collaborators, credentials, and other
// Yggdrasil Core resources via the HTTP API.
//
// Configuration (env):
//
//	YGGDRASIL_URL   — base URL of the Yggdrasil Core API (required)
//	                  e.g. http://yggdrasil-core:9080
//	YGGDRASIL_TOKEN — bearer token (admin session JWT) used for API calls
//
// Usage:
//
//	yggdrasil auth passwords setup-token --collaborator <slug>
//	yggdrasil auth passwords setup-token --id <uuid>
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "yggdrasil",
	Short: "Yggdrasil Core admin CLI",
	Long:  "Administrative CLI for the Yggdrasil Core API.",
	// SilenceUsage keeps cobra from printing usage on every RunE error.
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(newAuthCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
