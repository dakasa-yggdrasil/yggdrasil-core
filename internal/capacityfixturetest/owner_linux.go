//go:build linux

package capacityfixturetest

import (
	"os/exec"
	"syscall"
)

// The kernel notifies the owner if the Go test process (including the Go
// runtime's starting thread) dies. The owner handles SIGTERM and attempts its
// bounded cleanup. An independent observer must still verify the receipt; a
// parent-death signal alone is not proof of successful cleanup.
func configureParentDeath(command *exec.Cmd) {
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Pdeathsig = syscall.SIGTERM
}
