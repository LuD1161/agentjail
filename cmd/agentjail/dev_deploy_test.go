package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevDeployRunsOneInstallPass(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required by scripts/dev-deploy.sh")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(wd, "..", "..", "scripts", "dev-deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	scriptPath := filepath.Join(root, "scripts", "dev-deploy.sh")
	writeDeployTestFile(t, scriptPath, script, 0o755)

	fakeBin := filepath.Join(root, "fake-bin")
	installHome := filepath.Join(root, "install")
	invocations := filepath.Join(root, "install-invocations")
	home := filepath.Join(root, "home")
	for _, agentDir := range []string{".claude", ".cursor", ".codex"} {
		if err := os.MkdirAll(filepath.Join(home, agentDir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeDeployTestFile(t, filepath.Join(fakeBin, "go"), []byte(fakeDeployGo), 0o755)
	writeDeployTestFile(t, filepath.Join(fakeBin, "git"), []byte("#!/bin/sh\nprintf 'test-version\\n'\n"), 0o755)
	writeDeployTestFile(t, filepath.Join(fakeBin, "pkill"), []byte("#!/bin/sh\nexit 1\n"), 0o755)
	writeDeployTestFile(t, filepath.Join(fakeBin, "pgrep"), []byte("#!/bin/sh\nexit 1\n"), 0o755)
	writeDeployTestFile(t, filepath.Join(fakeBin, "launchctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	writeDeployTestFile(t, filepath.Join(fakeBin, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755)

	cmd := exec.Command(bash, scriptPath)
	cmd.Dir = root
	cmd.Env = deployTestEnv(map[string]string{
		"AGENTJAIL_DEPLOY_TEST_LOG": invocations,
		"AGENTJAIL_HOME":            installHome,
		"HOME":                      home,
		"PATH":                      fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dev-deploy.sh failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(invocations)
	if err != nil {
		t.Fatalf("read installer invocations: %v\n%s", err, out)
	}
	if calls := strings.Fields(strings.TrimSpace(string(got))); len(calls) != 2 || calls[0] != "install" || calls[1] != "--all" {
		t.Fatalf("installer invocations = %q, want exactly one %q\n%s", strings.TrimSpace(string(got)), "install --all", out)
	}
}

func writeDeployTestFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func deployTestEnv(overrides map[string]string) []string {
	env := os.Environ()
	for key, value := range overrides {
		prefix := key + "="
		for i := 0; i < len(env); i++ {
			if strings.HasPrefix(env[i], prefix) {
				env = append(env[:i], env[i+1:]...)
				i--
			}
		}
		env = append(env, prefix+value)
	}
	return env
}

const fakeDeployGo = `#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	-o)
		out="$2"
		shift 2
		;;
	*) shift ;;
	esac
done
mkdir -p "$(dirname "$out")"
if [ "$(basename "$out")" = "agentjail" ]; then
	cat > "$out" <<'STUB'
#!/bin/sh
set -eu
case "${1:-}" in
install)
	printf '%s\n' "$*" >> "$AGENTJAIL_DEPLOY_TEST_LOG"
	mkdir -p "$AGENTJAIL_HOME/bin"
	;;
status)
	printf 'daemon              ✓ running\n'
	;;
esac
STUB
else
	printf '#!/bin/sh\nexit 0\n' > "$out"
fi
chmod +x "$out"
`
