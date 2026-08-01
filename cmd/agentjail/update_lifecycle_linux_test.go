//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LuD1161/agentjail/internal/selfupdate"
	"github.com/LuD1161/agentjail/internal/wire"
)

const (
	lifecycleHelperEnv     = "AGENTJAIL_UPDATE_LIFECYCLE_HELPER"
	lifecycleHelperSocket  = "AGENTJAIL_UPDATE_LIFECYCLE_SOCKET"
	lifecycleHelperVersion = "AGENTJAIL_UPDATE_LIFECYCLE_VERSION"
	lifecycleOldGeneration = "old-agentjail"
	lifecycleNewGeneration = "fake-binary:agentjail"
)

// TestUpdateLifecycleDaemonHelper is the live process managed by
// liveUpdateSupervisor. It implements only the versioned control ping needed
// to prove which installed generation is actually serving.
func TestUpdateLifecycleDaemonHelper(t *testing.T) {
	if os.Getenv(lifecycleHelperEnv) != "1" {
		return
	}
	socketPath := os.Getenv(lifecycleHelperSocket)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		var req wire.ControlRequest
		decodeErr := json.NewDecoder(conn).Decode(&req)
		resp := wire.ControlResponse{OK: decodeErr == nil && req.Type == wire.ControlType && req.Op == wire.ControlOpPing}
		if resp.OK {
			resp.Version = os.Getenv(lifecycleHelperVersion)
		} else {
			resp.Error = "unsupported request"
		}
		_ = json.NewEncoder(conn).Encode(resp)
		_ = conn.Close()
	}
}

type liveUpdateSupervisor struct {
	t             *testing.T
	installDir    string
	socketPath    string
	process       *exec.Cmd
	failNew       bool
	restartSeen   []string
	activatedPIDs []int
}

func newLiveUpdateSupervisor(t *testing.T, installDir string) *liveUpdateSupervisor {
	t.Helper()
	runtimeDir, err := os.MkdirTemp("/tmp", "agentjail-update-live-*")
	if err != nil {
		t.Fatal(err)
	}
	s := &liveUpdateSupervisor{
		t:          t,
		installDir: installDir,
		socketPath: filepath.Join(runtimeDir, "daemon.sock"),
	}
	t.Cleanup(func() {
		s.stop()
		_ = os.RemoveAll(runtimeDir)
	})
	return s
}

func (s *liveUpdateSupervisor) installedGeneration() (string, error) {
	b, err := os.ReadFile(filepath.Join(s.installDir, "agentjail"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *liveUpdateSupervisor) restart(target string) error {
	if target != systemdUnitFilename {
		return errors.New("unexpected supervisor target: " + target)
	}
	s.stop()
	generation, err := s.installedGeneration()
	if err != nil {
		return err
	}
	s.restartSeen = append(s.restartSeen, generation)
	if s.failNew && generation == lifecycleNewGeneration {
		return errors.New("injected activation failure")
	}
	return s.start(generation)
}

func (s *liveUpdateSupervisor) start(version string) error {
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpdateLifecycleDaemonHelper$")
	cmd.Env = append(os.Environ(),
		lifecycleHelperEnv+"=1",
		lifecycleHelperSocket+"="+s.socketPath,
		lifecycleHelperVersion+"="+version,
	)
	if err := cmd.Start(); err != nil {
		return err
	}
	s.process = cmd
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		liveness, running, _ := probeDaemonDetails(s.socketPath, 100*time.Millisecond)
		if liveness == daemonHealthy && running == version {
			s.activatedPIDs = append(s.activatedPIDs, cmd.Process.Pid)
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	s.stop()
	return errors.New("helper daemon did not answer a versioned ping")
}

func (s *liveUpdateSupervisor) stop() {
	if s.process != nil {
		_ = s.process.Process.Kill()
		_ = s.process.Wait()
		s.process = nil
	}
	_ = os.Remove(s.socketPath)
}

func seedLiveUpdateInstall(t *testing.T, installDir string) {
	t.Helper()
	for name, content := range map[string]string{
		"agentjail":      lifecycleOldGeneration,
		"agentjail-hook": "old-hook",
	} {
		if err := os.WriteFile(filepath.Join(installDir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := selfupdate.EnsureRoleSymlinks(installDir); err != nil {
		t.Fatal(err)
	}
}

func TestPerformUpdateLiveActivation(t *testing.T) {
	installDir := configureFakeUpdate(t, selfupdate.UpdateBinaries)
	seedLiveUpdateInstall(t, installDir)
	supervisor := newLiveUpdateSupervisor(t, installDir)
	if err := supervisor.start(lifecycleOldGeneration); err != nil {
		t.Fatal(err)
	}
	oldPID := supervisor.activatedPIDs[0]
	setUpdateRestartDaemon(t, supervisor.restart)

	if code := performUpdate(installDir, "linux", "amd64", false); code != 0 {
		t.Fatalf("performUpdate() = %d, want 0", code)
	}
	if len(supervisor.restartSeen) != 1 || supervisor.restartSeen[0] != lifecycleNewGeneration {
		t.Fatalf("restart generations = %v, want [%s]", supervisor.restartSeen, lifecycleNewGeneration)
	}
	if len(supervisor.activatedPIDs) != 2 || supervisor.activatedPIDs[1] == oldPID {
		t.Fatalf("activated PIDs = %v; want a distinct updated daemon", supervisor.activatedPIDs)
	}
	liveness, running, err := probeDaemonDetails(supervisor.socketPath, time.Second)
	if err != nil || liveness != daemonHealthy || running != lifecycleNewGeneration {
		t.Fatalf("updated daemon probe = (%v, %q, %v), want healthy %q", liveness, running, err, lifecycleNewGeneration)
	}
}

func TestPerformUpdateLiveActivationFailureRollsBack(t *testing.T) {
	installDir := configureFakeUpdate(t, selfupdate.UpdateBinaries)
	seedLiveUpdateInstall(t, installDir)
	supervisor := newLiveUpdateSupervisor(t, installDir)
	supervisor.failNew = true
	if err := supervisor.start(lifecycleOldGeneration); err != nil {
		t.Fatal(err)
	}
	oldPID := supervisor.activatedPIDs[0]
	setUpdateRestartDaemon(t, supervisor.restart)

	if code := performUpdate(installDir, "linux", "amd64", false); code != 1 {
		t.Fatalf("performUpdate() = %d, want 1", code)
	}
	wantRestarts := []string{lifecycleNewGeneration, lifecycleOldGeneration}
	if strings.Join(supervisor.restartSeen, "\x00") != strings.Join(wantRestarts, "\x00") {
		t.Fatalf("restart generations = %v, want %v", supervisor.restartSeen, wantRestarts)
	}
	if len(supervisor.activatedPIDs) != 2 || supervisor.activatedPIDs[1] == oldPID {
		t.Fatalf("activated PIDs = %v; want the restored daemon in a new process", supervisor.activatedPIDs)
	}
	liveness, running, err := probeDaemonDetails(supervisor.socketPath, time.Second)
	if err != nil || liveness != daemonHealthy || running != lifecycleOldGeneration {
		t.Fatalf("restored daemon probe = (%v, %q, %v), want healthy %q", liveness, running, err, lifecycleOldGeneration)
	}
	for _, name := range selfupdate.UpdateBinaries {
		generation, readErr := os.ReadFile(filepath.Join(installDir, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if name == "agentjail" && strings.TrimSpace(string(generation)) != lifecycleOldGeneration {
			t.Errorf("restored agentjail = %q, want %q", generation, lifecycleOldGeneration)
		}
	}
}
