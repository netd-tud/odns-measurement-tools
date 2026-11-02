package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Scan_output_path creates a directory for one standalone UDP or TCP scan.
func Scan_output_path(root, protocol string, started time.Time) (string, error) {
	if protocol != "udp" && protocol != "tcp" {
		return "", fmt.Errorf("unsupported scan protocol %q", protocol)
	}
	if root == "" {
		root = filepath.Join("data", "raw")
	}
	started = started.UTC()
	parent := filepath.Join(root, protocol)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return "", fmt.Errorf("create scan output directory: %w", err)
	}
	dir := filepath.Join(parent, started.Format("2006-01-02_15-04-05"))
	// Refuse to reuse a scan directory, so an existing result cannot be truncated.
	if err := os.Mkdir(dir, 0755); err != nil {
		return "", fmt.Errorf("create scan output directory: %w", err)
	}
	return filepath.Join(dir, "odns_"+protocol+"_scan_"+started.Format("2006-01-02_15-04")+".csv.gz"), nil
}
