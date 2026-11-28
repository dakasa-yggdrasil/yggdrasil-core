//go:build !linux

package repository

func nativeReadinessReadFile(string, int64, bool) ([]byte, error) { return nil, errNativeReadinessRun }
