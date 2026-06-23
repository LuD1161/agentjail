// swap.go — atomic binary replacement helpers shared by CLI and daemon.
package selfupdate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// UpdateBinaries is the ordered list of binaries placed in $INSTALL_DIR,
// matching install.sh exactly.
var UpdateBinaries = []string{
	"agentjail",
	"agentjail-hook",
	"agentjail-daemon",
	"agentjail-shield",
	"agentjail-netproxy",
}

// CopyFile copies the file at src to dst, creating dst if needed.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src %q: %w", src, err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create dst %q: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %q → %q: %w", src, dst, err)
	}
	return nil
}

// AtomicReplaceBinary copies src to a temp file in the same directory as dst,
// sets mode 0755, then renames over dst. Crash-safe: dst is only swapped on a
// successful rename; a failure mid-flight leaves dst untouched.
func AtomicReplaceBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agentjail-update-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return os.Rename(tmpName, dst)
}
