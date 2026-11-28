//go:build !linux

package addons

// Installing Native authority is Linux-only; absent configuration still keeps
// every platform's existing process behavior unchanged.
func nativeWorkerReadRuntimeFile(string) ([]byte, error) { return nil, errNativeWorkerInstallation }
