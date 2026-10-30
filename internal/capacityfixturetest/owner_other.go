//go:build !linux

package capacityfixturetest

import "os/exec"

// Parent-death signaling is only used by the Linux qualification runner.
func configureParentDeath(*exec.Cmd) {}
