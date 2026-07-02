/* cbridge_header.h — Public C API for the agentjail WireGuard tunnel.
 *
 * This header is used by the macOS NETransparentProxyProvider Swift extension
 * to call into the Go WireGuard tunnel compiled as a static library
 * (libagentjail_tunnel.a).
 *
 * The API is per-connection (L4): the Swift extension receives individual TCP
 * flows and UDP datagrams from NETransparentProxyProvider and bridges them
 * through this API. There is no raw packet (L3) interface.
 *
 * Build the library with:
 *   make tunnel-clib
 *
 * Swift bridging: import this header via the extension's bridging header or
 * a module map.
 */

#ifndef AGENTJAIL_TUNNEL_H
#define AGENTJAIL_TUNNEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * wg_netstack_init — parse a wg-quick config and bring up the WireGuard
 * tunnel (gVisor netstack + wireguard-go device).
 *
 * conf   : NUL-terminated wg-quick config string containing [Interface]
 *          PrivateKey/Address and [Peer] PublicKey/Endpoint.
 * errBuf : caller-allocated buffer for error messages.
 * errLen : size of errBuf in bytes.
 *
 * Returns 0 on success, -1 on error (errBuf populated).
 * Idempotent — safe to call multiple times.
 */
int wg_netstack_init(const char* conf, char* errBuf, int errLen);

/*
 * wg_netstack_wait_handshake — block until the WireGuard peer completes
 * a handshake or the timeout elapses.
 *
 * timeoutMs : maximum wait time in milliseconds.
 *
 * Returns 0 on successful handshake, -1 on timeout.
 * Must be called AFTER wg_netstack_init and BEFORE driving TCP/UDP flows.
 */
int wg_netstack_wait_handshake(int timeoutMs);

/*
 * wg_netstack_tcp_connect — dial a TCP connection through the tunnel.
 *
 * host      : NUL-terminated IP address string (must be an IP literal,
 *             not a hostname — use wg_netstack_resolve first).
 * port      : destination port number.
 * timeoutMs : dial timeout in milliseconds (<=0 for no timeout).
 * errBuf    : caller-allocated error buffer.
 * errLen    : size of errBuf.
 *
 * Returns a positive connection ID on success, -1 on failure.
 * The connection ID is opaque — pass it to _send/_recv/_close_conn.
 */
int64_t wg_netstack_tcp_connect(const char* host, int port, int timeoutMs,
                                char* errBuf, int errLen);

/*
 * wg_netstack_udp_connect — dial a UDP "connection" through the tunnel
 * (fixed remote address, datagram semantics).
 *
 * host   : NUL-terminated IP address string.
 * port   : destination port number.
 * errBuf : caller-allocated error buffer.
 * errLen : size of errBuf.
 *
 * Returns a positive connection ID on success, -1 on failure.
 */
int64_t wg_netstack_udp_connect(const char* host, int port,
                                char* errBuf, int errLen);

/*
 * wg_netstack_send — write data to a connection.
 *
 * connID  : connection ID from tcp_connect or udp_connect.
 * data    : pointer to the data to send.
 * dataLen : number of bytes to send.
 *
 * Returns the number of bytes written, or -1 on error.
 * May block until the receiver's window opens (TCP back-pressure).
 */
int wg_netstack_send(int64_t connID, const char* data, int dataLen);

/*
 * wg_netstack_recv — read data from a connection (BLOCKING).
 *
 * connID : connection ID.
 * buf    : caller-allocated receive buffer.
 * bufLen : size of buf in bytes.
 *
 * Returns:
 *   > 0  — number of bytes received.
 *     0  — EOF (connection closed cleanly by remote).
 *    -1  — error (connection reset, ID not found, etc.).
 *
 * This call BLOCKS until data is available. The Swift caller must run
 * it on a dedicated background thread (pthread or dispatch queue).
 */
int wg_netstack_recv(int64_t connID, char* buf, int bufLen);

/*
 * wg_netstack_close_conn — close a specific connection and free its slot.
 *
 * connID : connection ID to close.
 *
 * Idempotent — safe to call on an already-closed or invalid ID.
 */
void wg_netstack_close_conn(int64_t connID);

/*
 * wg_netstack_resolve — resolve a hostname to an IPv4 address through
 * the tunnel's DNS (1.1.1.1:53 via the netstack).
 *
 * host   : NUL-terminated hostname (or IP literal, returned as-is).
 * outBuf : caller-allocated buffer for the resolved IP string.
 * outLen : size of outBuf in bytes.
 *
 * Returns 0 on success (IP written to outBuf), -1 on error.
 */
int wg_netstack_resolve(const char* host, char* outBuf, int outLen);

/*
 * wg_netstack_close — shut down the entire WireGuard tunnel.
 *
 * Closes the wireguard-go device and gVisor stack. All open connections
 * become invalid. Safe to call when not running.
 */
void wg_netstack_close(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AGENTJAIL_TUNNEL_H */
