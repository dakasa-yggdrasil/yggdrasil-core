//go:build capacitytest && !nativequalification

package main

import "errors"

func seedAndRun(bool) error { return errors.New("synthetic seed requires nativequalification build") }
