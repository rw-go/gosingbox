// Package prestart implements the preStart plugin's cleanupSockets stage: it
// removes stale unix socket files before the data plane starts, mirroring the
// official node's PreStartService.
package prestart

import (
	"os"
	"path/filepath"
)

// maxMatchesPerPattern caps glob expansion to bound work on wildcard patterns,
// matching the official node's safeguard.
const maxMatchesPerPattern = 256

// CleanupSockets removes unix socket files matching the given glob patterns.
// Non-socket files and missing paths are skipped. Returns the number of socket
// files removed.
func CleanupSockets(files []string) int {
	removed := 0
	for _, pattern := range files {
		if pattern == "" {
			continue
		}
		paths, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(paths) > maxMatchesPerPattern {
			paths = paths[:maxMatchesPerPattern]
		}
		for _, p := range paths {
			fi, err := os.Lstat(p)
			if err != nil || fi.Mode()&os.ModeSocket == 0 {
				continue
			}
			if err := os.Remove(p); err == nil {
				removed++
			}
		}
	}
	return removed
}
