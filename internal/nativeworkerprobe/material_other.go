//go:build !linux

package nativeworkerprobe

import (
	"os"
	"time"
)

func secretStatAllowed(os.FileInfo) bool            { return false }
func secretStatEqual(os.FileInfo, os.FileInfo) bool { return false }
func loadMaterial(string, string, time.Time) (*material, error) {
	return nil, ErrUnavailable
}
