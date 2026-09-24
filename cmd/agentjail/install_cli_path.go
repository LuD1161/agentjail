package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// installCLIPath exposes the CLI without recording consent for agent launch shims.
func installCLIPath(home string) error {
	binDir := filepath.Join(home, ".agentjail", "bin")
	stateDir := filepath.Dir(binDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	quotedBin := shellQuotePath(binDir)
	environment := "# agentjail shell environment\ncase \"$PATH\" in\n    " + quotedBin + "|" + quotedBin + ":*) ;;\n    *) export PATH=" + quotedBin + ":\"$PATH\" ;;\nesac\n"
	if err := writeCLIPathFile(filepath.Join(stateDir, "env"), []byte(environment), 0o644); err != nil {
		return fmt.Errorf("write CLI environment: %w", err)
	}
	if os.Getenv("AGENTJAIL_NO_MODIFY_PATH") == "1" {
		return nil
	}
	rc, line := cliShellProfile(home, os.Getenv("SHELL"), os.Getenv("ZDOTDIR"), currentGOOS)
	existing, err := os.ReadFile(rc)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read CLI shell profile: %w", err)
	}
	updated := reconcileCLIPathBlock(string(existing), line)
	if updated == string(existing) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(rc), 0o700); err != nil {
		return fmt.Errorf("create CLI shell profile directory: %w", err)
	}
	if err := writeCLIPathFile(rc, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write CLI shell profile: %w", err)
	}
	return nil
}

func cliShellProfile(home, shell, zdotdir, goos string) (string, string) {
	if shell == "" && goos == "darwin" {
		shell = "zsh"
	}
	line := `export PATH="$HOME/.agentjail/bin:$PATH"`
	switch filepath.Base(shell) {
	case "zsh":
		if zdotdir != "" {
			return filepath.Join(zdotdir, ".zshrc"), line
		}
		return filepath.Join(home, ".zshrc"), line
	case "bash":
		if goos == "darwin" {
			return filepath.Join(home, ".bash_profile"), line
		}
		return filepath.Join(home, ".bashrc"), line
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), `fish_add_path "$HOME/.agentjail/bin"`
	default:
		return filepath.Join(home, ".profile"), line
	}
}

func reconcileCLIPathBlock(content, line string) string {
	lines := strings.Split(content, "\n")
	result := make([]string, 0, len(lines)+2)
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != pathRCMarker {
			result = append(result, lines[i])
			continue
		}
		if i+1 < len(lines) && strings.Contains(lines[i+1], ".agentjail/bin") {
			i++
		}
	}
	return strings.TrimRight(strings.Join(result, "\n"), "\n") + "\n\n" + pathRCMarker + "\n" + line + "\n"
}

func shellQuotePath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
}

func writeCLIPathFile(path string, data []byte, fallbackMode os.FileMode) error {
	mode := fallbackMode
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			path = resolved
			info, err = os.Stat(path)
			if err != nil {
				return err
			}
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular file: %s", path)
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWrite(path, data, mode)
}
