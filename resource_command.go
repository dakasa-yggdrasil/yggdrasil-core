package main

import (
	"io"
	"strings"
)

// Dispatch the exact kernel reader before runtime construction or credentials.
// Other arguments retain Core's existing startup behavior. Callbacks are private
// CI seams; no path, environment variable or runtime endpoint selects a reader.
func dispatchCPUCapacityCommand(args []string, out, diagnostic io.Writer, start func(), read func() (cpuCapacityRuntime, error)) int {
	if len(args) == 1 && args[0] == printCPUCapacityArgument {
		return printCPUCapacityRuntime(out, diagnostic, read)
	}
	for _, argument := range args {
		if argument == printCPUCapacityArgument || strings.HasPrefix(argument, printCPUCapacityArgument+"=") {
			_, _ = io.WriteString(diagnostic, "unsupported CPU capacity arguments\n")
			return 2
		}
	}
	start()
	return 0
}
