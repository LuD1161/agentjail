package hostproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseCommandExactArgv(t *testing.T) {
	got, err := ParseCommand("agentjail proxy --reason 'inspect the signed build' -- benign \"space value\" 'semi;pipe|glob*$()`'")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"benign", "space value", "semi;pipe|glob*$()`"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
}

func TestParseCommandRejectsAmbiguousShell(t *testing.T) {
	for _, command := range []string{
		"agentjail proxy -- tool",
		"agentjail proxy --reason '' -- tool",
		"agentjail proxy -- tool && other",
		"agentjail proxy -- $TOOL",
		"agentjail proxy -- tool > out",
		"agentjail proxy -- tool\nother",
		"agentjail proxy -- tool # hidden",
		"PATH=/tmp agentjail proxy -- tool",
		"agentjail proxy tool",
		"agentjail proxy --",
	} {
		if _, err := ParseCommand(command); err == nil {
			t.Errorf("ParseCommand(%q) error = %v", command, err)
		}
	}
}

func TestParseArgsRequiresBoundedReason(t *testing.T) {
	if _, err := ParseArgs([]string{"--", "tool"}); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("missing reason error = %v", err)
	}
	if _, err := ParseArgs([]string{"--reason", strings.Repeat("x", MaxReasonBytes+1), "--", "tool"}); !errors.Is(err, ErrReasonInvalid) {
		t.Fatalf("oversized reason error = %v", err)
	}
}

func TestResolveAndPolicyCanonicalizeSymlink(t *testing.T) {
	dir := t.TempDir()
	denied := filepath.Join(dir, "python3.13")
	if err := os.WriteFile(denied, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "friendly")
	if err := os.Symlink(denied, link); err != nil {
		t.Fatal(err)
	}
	target, err := Resolve(dir, dir, []string{"friendly", "arg"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(denied)
	if err != nil {
		t.Fatal(err)
	}
	if target.Executable != want {
		t.Fatalf("executable = %q, want %q", target.Executable, want)
	}
	if got := Evaluate(target); got.Action != ActionDeny {
		t.Fatalf("decision = %+v", got)
	}
}

func TestPolicyCategoriesAndBenignShebang(t *testing.T) {
	for _, name := range []string{"git", "gh", "aws", "kubectl", "helm", "terraform", "tofu", "gcloud", "az", "sh", "bash", "zsh", "python", "python3", "python3.13", "node", "node20", "ruby3.1", "php8.4", "env", "xargs", "sudo", "busybox", "npx", "npm", "uv", "uvx", "agentjail", "agentjail-daemon"} {
		if got := Evaluate(Target{Executable: "/usr/bin/" + name, Argv: []string{name}}); got.Action != ActionDeny {
			t.Errorf("%s decision = %+v", name, got)
		}
	}
	if got := Evaluate(Target{Executable: "/opt/bin/rdt", Argv: []string{"rdt", "--help"}}); got.Action != ActionAsk {
		t.Fatalf("benign decision = %+v", got)
	}
}

func TestAuthorizationExactBindingsAndOneUse(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewManager(strings.NewReader(strings.Repeat("a", 64)), time.Minute)
	target := Target{Executable: "/opt/bin/rdt", Argv: []string{"rdt", "--help"}}
	auth, err := m.Issue(Authorization{
		SessionID: "s", Target: target, CWD: "/repo", Root: "/repo", Path: "/opt/bin",
		Reason: "inspect the signed build", BrokerPID: 42, FreshAfter: 10,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Redeem(RedeemRequest{
		Proof: auth.Proof, SessionID: "s", Target: target, Reason: auth.Reason, CWD: "/repo", PeerPID: 42,
		PeerChainFresh: true, CurrentTime: now.Add(time.Second),
	})
	if err != nil || got.Proof != auth.Proof {
		t.Fatalf("redeem = %+v, %v", got, err)
	}
	if _, err := m.Redeem(RedeemRequest{Proof: auth.Proof}); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestAuthorizationMismatchBurnsProof(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewManager(strings.NewReader(strings.Repeat("b", 64)), time.Minute)
	target := Target{Executable: "/opt/bin/rdt", Argv: []string{"rdt"}}
	auth, err := m.Issue(Authorization{SessionID: "s", Target: target, Reason: "inspect the signed build", CWD: "/repo", Root: "/repo", Path: "/bin", BrokerPID: 42, FreshAfter: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	bad := target
	bad.Argv = []string{"rdt", "changed"}
	if _, err := m.Redeem(RedeemRequest{Proof: auth.Proof, SessionID: "s", Target: bad, Reason: auth.Reason, CWD: "/repo", PeerPID: 42, PeerChainFresh: true, CurrentTime: now}); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err := m.Redeem(RedeemRequest{Proof: auth.Proof}); !errors.Is(err, ErrReplay) {
		t.Fatalf("post-mismatch replay error = %v", err)
	}
}

func TestAuthorizationRejectsExpiredCWDAndSession(t *testing.T) {
	now := time.Unix(100, 0)
	target := Target{Executable: "/opt/bin/rdt", Argv: []string{"rdt"}}
	for _, test := range []struct {
		name   string
		mutate func(*RedeemRequest)
	}{
		{name: "expired", mutate: func(req *RedeemRequest) { req.CurrentTime = now.Add(2 * time.Minute) }},
		{name: "cwd", mutate: func(req *RedeemRequest) { req.CWD = "/repo/other" }},
		{name: "session", mutate: func(req *RedeemRequest) { req.SessionID = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := NewManager(strings.NewReader(strings.Repeat(test.name, 64)), time.Minute)
			auth, err := m.Issue(Authorization{SessionID: "s", Target: target, Reason: "inspect the signed build", CWD: "/repo", Root: "/repo", Path: "/bin", BrokerPID: 42, FreshAfter: 1}, now)
			if err != nil {
				t.Fatal(err)
			}
			req := RedeemRequest{Proof: auth.Proof, SessionID: "s", Target: target, Reason: auth.Reason, CWD: "/repo", PeerPID: 42, PeerChainFresh: true, CurrentTime: now}
			test.mutate(&req)
			if _, err := m.Redeem(req); !errors.Is(err, ErrAuthorization) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestUnixExecutorArgvExitAndOutput(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix executor")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s' \"$1\"\nprintf '%s' err >&2\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	result := NewExecutor().Execute(context.Background(), Target{Executable: helper, Argv: []string{"helper", "a;$(x)|*"}}, dir, time.Second, 1024, nil)
	if result.ExitCode != 42 || string(result.Stdout) != "a;$(x)|*" || string(result.Stderr) != "err" {
		t.Fatalf("result = %+v", result)
	}
}

func TestUnixExecutorOutputLimit(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix executor")
	}
	result := NewExecutor().Execute(context.Background(), Target{Executable: "/usr/bin/yes", Argv: []string{"yes"}}, t.TempDir(), time.Second, 4096, nil)
	if !result.Truncated || result.Reason != "output_limit" || len(result.Stdout)+len(result.Stderr) != 4096 {
		t.Fatalf("result = %+v, bytes=%d", result, len(result.Stdout)+len(result.Stderr))
	}
}

func TestUnixExecutorOutputLimitFastExit(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix executor")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "overflow.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nhead -c 4097 /dev/zero\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		result := NewExecutor().Execute(context.Background(), Target{Executable: helper, Argv: []string{"overflow"}}, dir, time.Second, 4096, nil)
		if !result.Truncated || result.Reason != "output_limit" {
			t.Fatalf("iteration %d result = %+v", i, result)
		}
	}
}

func TestUnixExecutorTimeoutKillsProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix executor")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	helper := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nsleep 30 &\necho $! > \"$1\"\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	result := NewExecutor().Execute(context.Background(), Target{Executable: helper, Argv: []string{"helper", pidFile}}, dir, 100*time.Millisecond, 1024, nil)
	if !result.TimedOut || result.Reason != "timeout" {
		t.Fatalf("result = %+v", result)
	}
	assertRecordedProcessGone(t, pidFile)
}

func TestUnixExecutorCancellationKillsProcessGroup(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix executor")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	helper := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nsleep 30 &\necho $! > \"$1\"\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	result := NewExecutor().Execute(ctx, Target{Executable: helper, Argv: []string{"helper", pidFile}}, dir, time.Second, 1024, nil)
	if result.Reason != "cancelled" {
		t.Fatalf("result = %+v", result)
	}
	assertRecordedProcessGone(t, pidFile)
}

func assertRecordedProcessGone(t *testing.T, pidFile string) {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(raw))
	for i := 0; i < 50; i++ {
		if runtime.GOOS == "darwin" {
			processID, convErr := strconv.Atoi(pid)
			if convErr != nil {
				t.Fatal(convErr)
			}
			if errors.Is(syscall.Kill(processID, 0), syscall.ESRCH) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
		if os.IsNotExist(err) || (err == nil && strings.Contains(string(stat), ") Z ")) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("descendant %s remained live after process-group kill", pid)
}

func TestUnixExecutorSpawnFailure(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix executor")
	}
	result := NewExecutor().Execute(context.Background(), Target{Executable: "/definitely/missing", Argv: []string{"missing"}}, t.TempDir(), time.Second, 1024, nil)
	if result.ExitCode != -1 || result.Reason != "spawn_failed" {
		t.Fatalf("result = %+v", result)
	}
}

func TestWithinRootBoundary(t *testing.T) {
	if !WithinRoot("/repo", "/repo/sub") || WithinRoot("/repo", "/repo2") {
		t.Fatal("root boundary check failed")
	}
}
