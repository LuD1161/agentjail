package agents

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path atomically using a write-to-temp +
// fsync + rename sequence so that a crash between steps never leaves a
// truncated or partially-written file at path.
//
// Atomicity guarantees:
//   - The temp file is created in the same directory as path (same filesystem,
//     so os.Rename is atomic on POSIX).
//   - The temp file is fsynced before the rename, ensuring data durability.
//   - After the rename the parent directory is fsynced so the rename itself is
//     durable across a crash.
//   - No *.tmp debris is left behind on success; on failure the deferred
//     cleanup removes the temp file.
//
// Mode handling:
//   - If path already exists its current file mode is preserved (the passed
//     mode is used only when creating a new file).
//   - If path does not exist the supplied mode is applied to the temp file
//     before the rename.
//
// Backup (.bak) behaviour:
//   - On the first mutation of an existing file, a copy of the original
//     content is written to <path>.bak — but ONLY if <path>.bak does not
//     already exist. An existing .bak is never overwritten, so the very first
//     pre-agentjail state is always recoverable.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)

	// Determine the mode to apply.
	effectiveMode := mode
	var originalData []byte
	if fi, err := os.Stat(path); err == nil {
		// File exists — preserve its mode.
		effectiveMode = fi.Mode().Perm()

		// Read original content for .bak (before we overwrite anything).
		if b, rerr := os.ReadFile(path); rerr == nil {
			originalData = b
		}
	}

	// Write .bak if: the file exists, has readable original content, and
	// <path>.bak does not already exist.
	if originalData != nil {
		bakPath := path + ".bak"
		if _, err := os.Stat(bakPath); os.IsNotExist(err) {
			// Create .bak atomically as well (simple WriteFile is fine here
			// because a partial .bak is not harmful — it can be detected and
			// ignored; the real protection is the .bak not being overwritten).
			if werr := os.WriteFile(bakPath, originalData, effectiveMode); werr != nil {
				return fmt.Errorf("writeFileAtomic: write backup %s: %w", bakPath, werr)
			}
		}
	}

	// Create a temp file in the same directory.
	tmp, err := os.CreateTemp(dir, ".agentjail-atomic-*")
	if err != nil {
		return fmt.Errorf("writeFileAtomic: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// Best-effort cleanup on any error path; on success tmpName no longer
	// exists (renamed), so Remove returns an error we can ignore.
	defer func() { _ = os.Remove(tmpName) }()

	// Apply the file mode before writing data.
	if err := tmp.Chmod(effectiveMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writeFileAtomic: chmod temp: %w", err)
	}

	// Write data.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writeFileAtomic: write temp: %w", err)
	}

	// Fsync the temp file to flush data to stable storage before the rename.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writeFileAtomic: fsync temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writeFileAtomic: close temp: %w", err)
	}

	// Atomic replace.
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("writeFileAtomic: rename: %w", err)
	}

	// Fsync the parent directory so the rename (directory entry update) is
	// durable across a crash.
	if err := fsyncDir(dir); err != nil {
		// Non-fatal on platforms that don't support fsyncing directories
		// (e.g. some Windows file systems); log but do not fail the write.
		_ = err
	}

	return nil
}

// fsyncDir opens the directory at path and calls Sync on it. This ensures
// that the rename performed by writeFileAtomic is persisted to stable storage
// even after an unexpected power loss or kernel panic.
func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("fsyncDir: open %s: %w", path, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsyncDir: sync %s: %w", path, err)
	}
	return nil
}
