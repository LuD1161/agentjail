//go:build linux

package shieldapp

import (
	"fmt"
	"net/rpc"

	"github.com/LuD1161/agentjail/internal/daemon"
)

// requestNamespace asks the daemon to create a network namespace with a veth
// pair for the given session. The daemon holds CAP_NET_ADMIN; the shield does
// not need any special privileges for this call.
//
// Protocol: Go stdlib net/rpc over a Unix domain socket. The daemon registers
// a NamespaceService; the shield calls its methods via rpc.Dial.
func requestNamespace(socketPath, sessionID string) (*daemon.CreateNamespaceResp, error) {
	client, err := rpc.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to agentjail-daemon: %w", err)
	}
	defer client.Close()

	req := daemon.CreateNamespaceReq{SessionID: sessionID}
	var resp daemon.CreateNamespaceResp
	if err := client.Call("NamespaceService.Create", &req, &resp); err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	return &resp, nil
}

// destroyNamespace asks the daemon to tear down the namespace for the given
// session. Idempotent: destroying a non-existent session is not an error.
func destroyNamespace(socketPath, sessionID string) error {
	client, err := rpc.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to agentjail-daemon: %w", err)
	}
	defer client.Close()

	req := daemon.DestroyNamespaceReq{SessionID: sessionID}
	var resp daemon.DestroyNamespaceResp
	if err := client.Call("NamespaceService.Destroy", &req, &resp); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	return nil
}
