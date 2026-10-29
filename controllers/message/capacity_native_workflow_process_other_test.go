//go:build !linux && !darwin && (!recoveryfixture || nativequalification)

package message

import (
	"errors"
	"os/exec"
)

// This source-owned PG16 fixture is only supported on its Linux and Mac owners.
func nativeFixtureConfigureProcess(cmd *exec.Cmd) { cmd.Path = "" }

func nativeFixtureJoinProcessGroup(*exec.Cmd) error {
	return errors.New("unsupported synthetic fixture owner")
}
