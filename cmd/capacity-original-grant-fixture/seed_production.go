//go:build capacitytest && !nativequalification

package main

import "errors"

func seedAndRun() error { return errors.New("synthetic seed requires nativequalification build") }
