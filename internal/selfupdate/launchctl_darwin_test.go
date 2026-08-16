//go:build darwin

package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestLaunchctlLoadBootoutBootstrapOrder(t *testing.T) {
	original := launchctlRun
	t.Cleanup(func() { launchctlRun = original })
	var calls [][]string
	launchctlRun = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "bootout" {
			return []byte("service absent"), errors.New("not found")
		}
		return nil, nil
	}

	if err := LaunchctlLoad("/tmp/com.agentjail.daemon.plist"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"bootout", launchctlTargetForPlist("/tmp/com.agentjail.daemon.plist")},
		{"bootstrap", "gui/" + uidString(), "/tmp/com.agentjail.daemon.plist"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestLaunchctlLoadTargetsExactService(t *testing.T) {
	original := launchctlRun
	t.Cleanup(func() { launchctlRun = original })
	var bootoutTargets []string
	launchctlRun = func(args ...string) ([]byte, error) {
		if args[0] == "bootout" {
			bootoutTargets = append(bootoutTargets, args[1])
		}
		return nil, nil
	}

	for _, plist := range []string{
		"/tmp/com.agentjail.daemon.plist",
		"/tmp/com.agentjail.secrets.plist",
	} {
		if err := LaunchctlLoad(plist); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"gui/" + uidString() + "/com.agentjail.daemon",
		"gui/" + uidString() + "/com.agentjail.secrets",
	}
	if !reflect.DeepEqual(bootoutTargets, want) {
		t.Fatalf("bootout targets = %v, want %v", bootoutTargets, want)
	}
}

func TestLaunchctlLoadFallsBackForOlderLaunchd(t *testing.T) {
	original := launchctlRun
	t.Cleanup(func() { launchctlRun = original })
	var calls []string
	launchctlRun = func(args ...string) ([]byte, error) {
		calls = append(calls, args[0])
		switch args[0] {
		case "bootstrap":
			return []byte("unsupported"), errors.New("exit 64")
		default:
			return nil, nil
		}
	}

	if err := LaunchctlLoad("/tmp/com.agentjail.daemon.plist"); err != nil {
		t.Fatal(err)
	}
	want := []string{"bootout", "bootstrap", "unload", "load"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func uidString() string {
	return fmt.Sprint(os.Getuid())
}
