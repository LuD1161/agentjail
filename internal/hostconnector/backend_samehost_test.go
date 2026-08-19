package hostconnector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LuD1161/agentjail/internal/grant"
)

func grantPrincipal() (Binding, error) {
	principal, err := grant.NewPrincipal("codex", "same-host")
	if err != nil {
		return Binding{}, err
	}
	return NewBinding(principal)
}

func TestSameHostBackendProbesConfiguredCDPOnly(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json/version" {
			t.Fatalf("probe path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"Browser":"Chrome/1","webSocketDebuggerUrl":"ws://127.0.0.1/devtools/browser/x"}`))
	}))
	defer fixture.Close()
	host, portText, err := net.SplitHostPort(fixture.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := NewDestination(host, uint16(port), "/json/version")
	if err != nil {
		t.Fatal(err)
	}
	connector, err := NewConnector("chrome-cdp", TransportCDP, destination, ProbeChromeCDP)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := grantPrincipal()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSameHostBackend().Activate(context.Background(), Activation{connector: connector, binding: principal})
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSameHostBackendRejectsProbeMismatch(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"Browser":"Chrome/1"}`)) }))
	defer fixture.Close()
	host, portText, _ := net.SplitHostPort(fixture.Listener.Addr().String())
	port, _ := net.LookupPort("tcp", portText)
	destination, _ := NewDestination(host, uint16(port), "/json/version")
	connector, _ := NewConnector("chrome-cdp", TransportCDP, destination, ProbeChromeCDP)
	binding, _ := grantPrincipal()
	_, err := NewSameHostBackend().Activate(context.Background(), Activation{connector: connector, binding: binding})
	if !errors.Is(err, ErrActivation) {
		t.Fatalf("Activate() error = %v, want probe failure", err)
	}
}
