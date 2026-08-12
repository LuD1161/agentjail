package hostproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrExecutable = errors.New("host proxy executable is unavailable")

func Resolve(pathValue, cwd string, argv []string) (Target, error) {
	if len(argv) == 0 || argv[0] == "" || !filepath.IsAbs(cwd) {
		return Target{}, ErrExecutable
	}
	name := argv[0]
	var candidate string
	if strings.ContainsRune(name, filepath.Separator) {
		candidate = name
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
		if err := executableFile(candidate); err != nil {
			return Target{}, err
		}
	} else {
		for _, dir := range filepath.SplitList(pathValue) {
			if dir == "" {
				dir = cwd
			} else if !filepath.IsAbs(dir) {
				dir = filepath.Join(cwd, dir)
			}
			try := filepath.Join(dir, name)
			if executableFile(try) == nil {
				candidate = try
				break
			}
		}
		if candidate == "" {
			return Target{}, fmt.Errorf("%w: %s", ErrExecutable, name)
		}
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return Target{}, fmt.Errorf("%w: resolve %s: %v", ErrExecutable, name, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || executableFile(resolved) != nil {
		return Target{}, fmt.Errorf("%w: %s", ErrExecutable, name)
	}
	return Target{Executable: filepath.Clean(resolved), Argv: append([]string(nil), argv...)}, nil
}

func executableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return ErrExecutable
	}
	return nil
}

func WithinRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	return root != "" && filepath.IsAbs(root) && filepath.IsAbs(path) &&
		(path == root || strings.HasPrefix(path, root+string(filepath.Separator)))
}
