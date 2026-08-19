//go:build linux

package hostconnector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/LuD1161/agentjail/internal/proxyctl"
)

const linuxContainerGuestSocketDir = "/run/agentjail/connectors"

// LinuxContainerConfig is created from shield-owned launch state. The token
// and session ID are already established by netproxy registration; they are
// never accepted from a guest request. RuntimeDir must be a private host-owned
// directory that the launcher bind-mounts into the container at the endpoint.
type LinuxContainerConfig struct {
	SessionID  SessionID
	Token      proxyctl.Token
	RuntimeDir string
}

// LinuxContainerBackend exposes one configured connector as a session-scoped
// AF_UNIX socket. The socket reverse-tunnels only that connector's synthetic
// netproxy authority; it never accepts a guest-selected host or port.
type LinuxContainerBackend struct {
	route       *NetproxyBackend
	config      LinuxContainerConfig
	proxyAddr   string
	dialTimeout time.Duration
}

func NewLinuxContainerBackend(socketPath, ctlToken string, config LinuxContainerConfig) (*LinuxContainerBackend, error) {
	route, err := NewNetproxyBackend(socketPath, ctlToken)
	if err != nil {
		return nil, err
	}
	if config.SessionID == "" || config.Token == "" || !validRuntimeDir(config.RuntimeDir) {
		return nil, ErrInvalidBinding
	}
	return &LinuxContainerBackend{
		route: route, config: config, proxyAddr: "127.0.0.1:9100", dialTimeout: time.Second,
	}, nil
}

func (b *LinuxContainerBackend) Activate(ctx context.Context, activation Activation) (Adapter, error) {
	if TransportCapabilityFor(IsolationLinuxContainer).State != StateAvailable {
		return nil, ErrPlatformUnavailable
	}
	if activation.Binding().Principal().SessionID() != b.config.SessionID {
		return nil, fmt.Errorf("%w: connector session does not match trusted launch", ErrActivation)
	}
	routeAdapter, err := b.route.Activate(ctx, activation)
	if err != nil {
		return nil, err
	}
	bridge, err := newLinuxConnectorBridge(b.config, activation.ConnectorID(), b.proxyAddr, b.dialTimeout)
	if err != nil {
		_ = routeAdapter.Close()
		return nil, fmt.Errorf("%w: create guest connector endpoint: %v", ErrActivation, err)
	}
	return &linuxContainerAdapter{route: routeAdapter, bridge: bridge}, nil
}

type linuxContainerAdapter struct {
	route  Adapter
	bridge *linuxConnectorBridge
}

func (a *linuxContainerAdapter) Close() error {
	return errors.Join(a.bridge.Close(), a.route.Close())
}

func (a *linuxContainerAdapter) GuestEndpoint() GuestEndpoint { return a.bridge.endpoint }

type linuxConnectorBridge struct {
	listener    net.Listener
	path        string
	endpoint    GuestEndpoint
	token       proxyctl.Token
	connectorID ConnectorID
	proxyAddr   string
	dialTimeout time.Duration
	done        chan struct{}
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

func newLinuxConnectorBridge(config LinuxContainerConfig, connectorID ConnectorID, proxyAddr string, dialTimeout time.Duration) (*linuxConnectorBridge, error) {
	if config.SessionID == "" || config.Token == "" || !validConnectorID(connectorID) || !validRuntimeDir(config.RuntimeDir) {
		return nil, ErrActivation
	}
	if proxyAddr == "" || dialTimeout <= 0 {
		return nil, ErrActivation
	}
	digest := sha256.Sum256([]byte(config.SessionID))
	sessionDir := filepath.Join(config.RuntimeDir, fmt.Sprintf("%x", digest[:16]))
	if err := os.Mkdir(sessionDir, 0o700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if !validRuntimeDir(sessionDir) {
		return nil, ErrActivation
	}
	path := filepath.Join(sessionDir, string(connectorID)+".sock")
	if err := removeOwnedSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if !validOwnedSocket(path) {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, ErrActivation
	}
	bridge := &linuxConnectorBridge{
		listener: listener,
		path:     path,
		endpoint: GuestEndpoint{isolation: IsolationLinuxContainer, socket: filepath.Join(linuxContainerGuestSocketDir, string(connectorID)+".sock")},
		token:    config.Token, connectorID: connectorID, proxyAddr: proxyAddr, dialTimeout: dialTimeout, done: make(chan struct{}),
	}
	bridge.wg.Add(1)
	go bridge.serve()
	return bridge, nil
}

func (b *linuxConnectorBridge) serve() {
	defer b.wg.Done()
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			select {
			case <-b.done:
				return
			default:
				continue
			}
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.forward(conn)
		}()
	}
}

func (b *linuxConnectorBridge) forward(guest net.Conn) {
	defer guest.Close()
	dialer := net.Dialer{Timeout: b.dialTimeout}
	proxy, err := dialer.Dial("tcp", b.proxyAddr)
	if err != nil {
		return
	}
	defer proxy.Close()
	target, ok := proxyctl.ConnectorAuthority(string(b.connectorID))
	if !ok {
		return
	}
	credential := base64.StdEncoding.EncodeToString([]byte(string(b.token) + ":"))
	if _, err := fmt.Fprintf(proxy, "CONNECT %s:443 HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n", target, credential); err != nil {
		return
	}
	reader := bufio.NewReader(proxy)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return
	}
	copyBoth(guest, bufferedConn{Conn: proxy, reader: reader})
}

func (b *linuxConnectorBridge) Close() error {
	var result error
	b.closeOnce.Do(func() {
		close(b.done)
		result = b.listener.Close()
		b.wg.Wait()
		if err := removeOwnedSocket(b.path); err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, err)
		}
	})
	return result
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func copyBoth(left, right io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(left, right); _ = left.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(right, left); _ = right.Close() }()
	wg.Wait()
}

func validRuntimeDir(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return false
	}
	return true
}

func removeOwnedSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || !validOwnedSocket(path) {
		return ErrActivation
	}
	return os.Remove(path)
}

func validOwnedSocket(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

var _ EndpointProvider = (*linuxContainerAdapter)(nil)
