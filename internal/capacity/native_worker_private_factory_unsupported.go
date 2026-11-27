//go:build !linux

package capacity

import (
	"context"
	"os"
	"time"
)

func nativePrivateReadFile(string, int64, bool) ([]byte, error) { return nil, errNativePrivateFactory }
func nativePrivateOpenExecutable(NativeWorkerPrivateFactoryConfig) (*os.File, error) {
	return nil, errNativePrivateFactory
}
func nativePrivateExecute(context.Context, *os.File, NativeWorkerPrivateFactoryConfig, []byte, time.Time) ([]byte, error) {
	return nil, errNativePrivateFactory
}
