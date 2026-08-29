// Package agentguidance owns AgentJail's bounded block in global coding-agent
// instruction files.
package agentguidance

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	MarkerStart = "<!-- BEGIN AGENTJAIL MANAGED BLOCK -->"
	MarkerEnd   = "<!-- END AGENTJAIL MANAGED BLOCK -->"

	Guidance = "This session runs inside AgentJail's OS-native safety sandbox, which governs host files and CLIs, MCP tools, credentials, and network access.\n" +
		"For required host file or CLI access, consult `agentjail proxy --help`; use MCP and credential tools normally so AgentJail can apply their approval flow, and stop if denied or rejected."

	ReconcileCommand = "_reconcile-guidance"
)

var managedBlock = []byte(MarkerStart + "\n" + Guidance + "\n" + MarkerEnd + "\n")

// RunReconciler asks a newly installed AgentJail binary to apply the guidance
// bundled with that release.
func RunReconciler(cliPath string) error {
	cmd := exec.Command(cliPath, ReconcileCommand)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("run updated guidance reconciler: %w: %s", err, bytes.TrimSpace(output))
	}
	return nil
}

// Reconcile appends the managed block or refreshes its contents in place.
func Reconcile(path string) (bool, error) {
	resolved, existing, mode, err := readDocument(path)
	if err != nil {
		return false, err
	}

	updated, changed, err := reconcile(existing)
	if err != nil || !changed {
		return changed, err
	}
	if resolved == "" {
		resolved = path
		if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
			return false, fmt.Errorf("create guidance directory: %w", err)
		}
	}
	if err := writeAtomic(resolved, updated, mode); err != nil {
		return false, err
	}
	return true, nil
}

// Remove deletes only the managed block and the separator AgentJail added.
func Remove(path string) (bool, error) {
	resolved, existing, mode, err := readDocument(path)
	if err != nil {
		return false, err
	}
	if resolved == "" {
		return false, nil
	}

	updated, changed, err := remove(existing)
	if err != nil || !changed {
		return changed, err
	}
	if err := writeAtomic(resolved, updated, mode); err != nil {
		return false, err
	}
	return true, nil
}

func reconcile(existing []byte) ([]byte, bool, error) {
	start, end, err := managedRange(existing)
	if err != nil {
		return nil, false, err
	}
	if start < 0 {
		start, end, err = legacyRange(existing)
		if err != nil {
			return nil, false, err
		}
		if start >= 0 {
			withoutLegacy := removeRange(existing, start, end, 1)
			updated, _, err := reconcile(withoutLegacy)
			return updated, true, err
		}
		if len(existing) == 0 {
			return append([]byte(nil), managedBlock...), true, nil
		}
		updated := make([]byte, 0, len(existing)+2+len(managedBlock))
		updated = append(updated, existing...)
		updated = append(updated, '\n', '\n')
		updated = append(updated, managedBlock...)
		return updated, true, nil
	}

	updated := make([]byte, 0, len(existing)-(end-start)+len(managedBlock))
	updated = append(updated, existing[:start]...)
	updated = append(updated, managedBlock...)
	updated = append(updated, existing[end:]...)
	return updated, !bytes.Equal(existing, updated), nil
}

func remove(existing []byte) ([]byte, bool, error) {
	start, end, err := managedRange(existing)
	if err != nil {
		return existing, false, err
	}
	if start < 0 {
		start, end, err = legacyRange(existing)
		if err != nil || start < 0 {
			return existing, false, err
		}
		return removeRange(existing, start, end, 1), true, nil
	}
	return removeRange(existing, start, end, 2), true, nil
}

func removeRange(existing []byte, start, end, ownedSeparators int) []byte {
	for removed := 0; removed < ownedSeparators && start > 0 && existing[start-1] == '\n'; removed++ {
		start--
	}
	updated := make([]byte, 0, len(existing)-(end-start))
	updated = append(updated, existing[:start]...)
	updated = append(updated, existing[end:]...)
	return updated
}

func legacyRange(content []byte) (int, int, error) {
	legacy := []byte(Guidance)
	count := bytes.Count(content, legacy)
	if count == 0 {
		return -1, -1, nil
	}
	if count > 1 {
		return -1, -1, fmt.Errorf("agentjail guidance has duplicate legacy blocks")
	}
	start := bytes.Index(content, legacy)
	end := start + len(legacy)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	return start, end, nil
}

func managedRange(content []byte) (int, int, error) {
	startMarker := []byte(MarkerStart)
	endMarker := []byte(MarkerEnd)
	if bytes.Count(content, startMarker) != bytes.Count(content, endMarker) {
		return -1, -1, fmt.Errorf("agentjail guidance has an unmatched managed-block marker")
	}
	if bytes.Count(content, startMarker) > 1 {
		return -1, -1, fmt.Errorf("agentjail guidance has duplicate managed blocks")
	}
	start := bytes.Index(content, startMarker)
	if start < 0 {
		return -1, -1, nil
	}
	endAt := bytes.Index(content, endMarker)
	if endAt < start {
		return -1, -1, fmt.Errorf("agentjail guidance managed-block markers are out of order")
	}
	end := endAt + len(endMarker)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	return start, end, nil
}

func readDocument(path string) (resolved string, content []byte, mode os.FileMode, err error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", nil, 0o600, nil
	}
	if err != nil {
		return "", nil, 0, fmt.Errorf("inspect guidance file: %w", err)
	}
	resolved = path
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err = filepath.EvalSymlinks(path)
		if err != nil {
			return "", nil, 0, fmt.Errorf("resolve guidance symlink: %w", err)
		}
		info, err = os.Stat(resolved)
		if err != nil {
			return "", nil, 0, fmt.Errorf("inspect guidance symlink target: %w", err)
		}
	}
	if !info.Mode().IsRegular() {
		return "", nil, 0, fmt.Errorf("guidance path is not a regular file: %s", path)
	}
	content, err = os.ReadFile(resolved)
	if err != nil {
		return "", nil, 0, fmt.Errorf("read guidance file: %w", err)
	}
	return resolved, content, info.Mode().Perm(), nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentjail-guidance-*")
	if err != nil {
		return fmt.Errorf("create guidance temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set guidance file mode: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write guidance file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync guidance file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close guidance file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace guidance file: %w", err)
	}
	return nil
}
