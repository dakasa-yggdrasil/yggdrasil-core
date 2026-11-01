// LAB-only diagnostic. It consumes untrusted stdin; it cannot authorize
// capacity recovery or verify the producer of the inventory.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/labhistorical"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: lab-historical-snapshot policy.json < untrusted-inventory.json")
		os.Exit(2)
	}
	policy, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "HOLD: policy unavailable")
		os.Exit(1)
	}
	wire, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	if err != nil || len(wire) > 2<<20 {
		fmt.Fprintln(os.Stderr, "HOLD: inventory unavailable or oversized")
		os.Exit(1)
	}
	snapshot, err := labhistorical.DiagnosticSnapshot(policy, wire, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, "HOLD: historical inputs did not validate")
		os.Exit(1)
	}
	result := struct {
		Schema              string      `json:"schema"`
		DiagnosticOnly      bool        `json:"diagnostic_only"`
		OriginAuthenticated bool        `json:"origin_authenticated"`
		RecoveryAuthorized  bool        `json:"recovery_authorized"`
		Snapshot            interface{} `json:"snapshot"`
	}{"lab_historical_snapshot_diagnostic_v1", true, false, false, snapshot}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
}
