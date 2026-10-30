//go:build !linux && !darwin && (!recoveryfixture || nativequalification)

package repository

import (
	"errors"
	"os/exec"
)

// This source-owned PG16 fixture is only supported on its Linux and Mac owners.
func floorFixtureConfigureProcess(cmd *exec.Cmd) { cmd.Path = "" }

func floorFixtureJoinProcessGroup(*exec.Cmd) error {
	return errors.New("unsupported synthetic fixture owner")
}
