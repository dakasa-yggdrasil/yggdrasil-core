//go:build !linux

package nativeworkerprobe

import "context"

func Run(context.Context) error { return ErrUnavailable }
