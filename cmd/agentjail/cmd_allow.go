// cmd_allow.go -- cobra command tree for `agentjail allow`.
//
// Subcommands:
//
//	agentjail allow host <host> [--ttl 1h] [--reason "..."]
//
// This command is agent-safe: it runs INSIDE the sandbox. It never talks to
// the netproxy control socket (agent-unreachable by construction); it only
// files a grant REQUEST on the data plane, through the standard proxy
// environment, at the netproxy sentinel authority
// (grant.agentjail.local). Filing a request grants nothing -- a human must
// approve it out-of-band with `agentjail grant approve` from a trusted
// terminal. See docs/adr/0044 (Phase 3 runtime host grants).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/hostgrant"
	"github.com/LuD1161/agentjail/internal/proxyctl"
	"github.com/spf13/cobra"
)

// sentinelAllowURL is the fixed authority + path the netproxy control plane
// recognizes as a grant request. It is never forwarded upstream by netproxy
// (see ADR 0044); it is a reserved sentinel, not a real DNS name.
const sentinelAllowURL = "http://grant.agentjail.local/allow"

// allowRequestTimeout bounds how long `agentjail allow host` waits for the
// netproxy sentinel to answer the GET before giving up.
const allowRequestTimeout = 10 * time.Second

var (
	allowHostTTL    string
	allowHostReason string
)

var allowCmd = &cobra.Command{
	Use:   "allow",
	Short: "Request a runtime widening of this session's network egress",
}

var allowHostCmd = &cobra.Command{
	Use:   "host <host>",
	Short: "Request that a host be added to this session's allowlist",
	Long: `Files a grant REQUEST for host with the running netproxy for the CURRENT
shielded session. This command only files intent -- it grants nothing by
itself. A human must run 'agentjail grants' and 'agentjail grant approve
<grant_id>' from a trusted terminal (outside the sandbox) to actually widen
egress.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runAllowHost(args[0], allowHostTTL, allowHostReason))
	},
}

func init() {
	allowHostCmd.Flags().StringVar(&allowHostTTL, "ttl", "1h", "How long the grant should last once approved (Go duration, e.g. 30m, 2h)")
	allowHostCmd.Flags().StringVar(&allowHostReason, "reason", "", "Optional justification shown to the human approver")

	allowCmd.AddCommand(allowHostCmd)
	rootCmd.AddCommand(allowCmd)
}

// allowGrantResponse is the JSON body netproxy returns on a successful
// (202 Accepted) grant request. Fields are best-effort display data --
// absence of a grant_id is not treated as an error.
type allowGrantResponse struct {
	GrantID string `json:"grant_id"`
	Host    string `json:"host"`
	TTLMs   int64  `json:"ttl_ms"`
}

// allowHTTPClient returns an *http.Client whose Transport resolves the proxy
// from the standard environment variables (HTTP_PROXY/HTTPS_PROXY/NO_PROXY,
// in Go's normal precedence) via http.ProxyFromEnvironment, exactly the same
// resolution netproxy's own data plane already relies on. It deliberately
// does NOT read a single env var manually so behavior matches whatever proxy
// configuration the shield actually injected.
func allowHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
		Timeout:   allowRequestTimeout,
	}
}

// runAllowHost validates host locally, then files a grant request with the
// netproxy sentinel through the standard proxy environment. It returns the
// process exit code.
func runAllowHost(host, ttl, reason string) int {
	validHost, err := hostgrant.Validate(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: %v\n", err)
		return 1
	}

	if ttl == "" {
		ttl = "1h"
	}
	if _, err := time.ParseDuration(ttl); err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: invalid --ttl %q: %v\n", ttl, err)
		return 1
	}

	if len(reason) > proxyctl.MaxReasonLen {
		fmt.Fprintf(os.Stderr, "agentjail allow host: --reason too long (%d > %d bytes)\n", len(reason), proxyctl.MaxReasonLen)
		return 1
	}

	q := url.Values{}
	q.Set("host", validHost)
	q.Set("ttl", ttl)
	if reason != "" {
		q.Set("reason", reason)
	}

	reqURL := sentinelAllowURL + "?" + q.Encode()
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: build request: %v\n", err)
		return 1
	}

	resp, err := allowHTTPClient().Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentjail allow host: request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, proxyctl.MaxControlMsgBytes))

	if resp.StatusCode == http.StatusAccepted {
		var parsed allowGrantResponse
		grantSuffix := ""
		if err := json.Unmarshal(body, &parsed); err == nil && parsed.GrantID != "" {
			grantSuffix = fmt.Sprintf(" (grant_id %s)", parsed.GrantID)
		}
		fmt.Printf("requested host %s (ttl %s) - pending human approval%s; run 'agentjail grants' in a trusted terminal to approve\n", validHost, ttl, grantSuffix)
		return 0
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = resp.Status
	}
	fmt.Fprintf(os.Stderr, "agentjail allow host: request refused (%d %s): %s\n", resp.StatusCode, http.StatusText(resp.StatusCode), msg)
	return 1
}
