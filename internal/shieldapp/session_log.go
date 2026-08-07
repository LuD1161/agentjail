package shieldapp

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const shieldLogKeep = 10

type shieldSessionLog struct {
	dir  string
	path string
	file *os.File
}

func openShieldSessionLog(stateDir string, now time.Time, pid int, verbose bool, stderr io.Writer) (*shieldSessionLog, *slog.Logger, error) {
	dir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("secure log directory: %w", err)
	}
	name := fmt.Sprintf("shield-%s-%d.log", now.UTC().Format("20060102T150405.000000000Z"), pid)
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open session log: %w", err)
	}

	var output io.Writer = file
	if verbose {
		output = io.MultiWriter(file, stderr)
	}
	logger := slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return &shieldSessionLog{dir: dir, path: path, file: file}, logger, nil
}

func (l *shieldSessionLog) Close() error {
	return l.file.Close()
}

func pruneOldShieldLogs(dir string, keep int, preservePath string) (int, error) {
	if keep < 1 {
		return 0, fmt.Errorf("keep must be positive")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read log directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "shield-") && strings.HasSuffix(name, ".log") {
			names = append(names, name)
		}
	}
	if len(names) <= keep {
		return 0, nil
	}

	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	preserveName := filepath.Base(preservePath)
	kept := map[string]struct{}{preserveName: {}}
	for _, name := range names {
		if len(kept) >= keep {
			break
		}
		kept[name] = struct{}{}
	}

	removed := 0
	for _, name := range names {
		if _, ok := kept[name]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("remove old session log: %w", err)
		}
		removed++
	}
	return removed, nil
}
