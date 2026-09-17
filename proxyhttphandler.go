package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/williambailey/pacproxy/pac"
)

const (
	// tunnelIdleKeepAlive is how long a completely idle tunneled TCP
	// connection waits before kernel keep-alive probes start. Probes keep
	// NAT/conntrack state warm so long-lived but quiet connections
	// (websockets, idle HTTPS keep-alive sessions, chat sockets) are far
	// less likely to be silently dropped mid-session.
	tunnelIdleKeepAlive = 30 * time.Second
	// tunnelKeepAliveInterval is the time between keep-alive probes.
	tunnelKeepAliveInterval = 10 * time.Second
	// tunnelKeepAliveCount is how many unanswered probes before the kernel
	// declares the peer dead so the tunnel tears down instead of leaking.
	tunnelKeepAliveCount = 3

	// tunnelCopyBufferSize sizes the pooled relay buffer for opaque
	// CONNECT tunnels. TLS records are at most ~16KiB, so 32KiB covers a
	// full record with headroom.
	tunnelCopyBufferSize = 32 * 1024
	// bodyCopyBufferSize sizes the pooled buffer used when streaming
	// proxied HTTP response bodies. Large transfers (file downloads) are
	// syscall-bound; a bigger buffer measurably raises throughput at a
	// negligible cost because the buffers come from a sync.Pool.
	bodyCopyBufferSize = 128 * 1024
	// tunnelDrainTimeout bounds how long the still-open direction of a
	// tunnel gets to finish once the peer has sent its FIN. Half-closing
	// lets in-flight bytes flush instead of being truncated (the previous
	// blanket 10ms deadline could do exactly that), while the timeout
	// stops one-sided peers from pinning a goroutine and descriptor
	// forever.
	tunnelDrainTimeout = 10 * time.Second

	// directConnectResponse is the canned handshake sent to the client for
	// a successful direct (bypassing any upstream proxy) CONNECT.
	directConnectResponse = "HTTP/1.0 200 Connection established\r\n\r\n"

	// connectHandshakeTimeout bounds how long an upstream proxy may take
	// to answer our CONNECT request. Without it a broken or hostile
	// upstream that accepts the TCP dial and stays silent wedges a
	// goroutine and two descriptors indefinitely.
	connectHandshakeTimeout = 15 * time.Second
)

// Buffer pools. sync.Pool keeps the allocations amortised: in steady state
// the proxy does zero allocation per copied byte, and unused buffers are
// swept by the GC, so pooled memory does not pile up as permanent
// residency.
var (
	tunnelBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tunnelCopyBufferSize)
			return &b
		},
	}
	bodyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, bodyCopyBufferSize)
			return &b
		},
	}
)

type proxyHTTPHandler struct {
	proxyFinder     pac.ProxyFinder
	proxySelector   pac.ProxySelector
	httpClient      *http.Client
	dialer          *net.Dialer
	nonProxyHandler http.Handler
}

func newProxyHTTPHandler(
	proxyFinder pac.ProxyFinder,
	proxySelector pac.ProxySelector,
	nonProxyHandler http.Handler,
) *proxyHTTPHandler {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		// DualStack (happy-eyeballs) keeps IPv6-broken networks from
		// stalling on AAAA before falling back to A records.
		DualStack: true,
	}
	transport := &http.Transport{
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		// Attempt HTTP/2 on TLS connections. Multiplexing plus larger
		// flow-control windows make parallel large downloads faster.
		ForceAttemptHTTP2: true,
		// ReadBufferSize/WriteBufferSize are intentionally left at the
		// stdlib default: they are allocated per pooled connection, so
		// inflating them would raise resident memory for thousands of
		// idle small connections. Bulk transfer speed instead comes from
		// the sync.Pool buffers in doHTTPProxy/relay below.
		//
		// With TLSClientConfig nil the transport installs the default
		// tls.Config, which includes a client session cache, so repeat
		// HTTPS connections to the same host resume in 1-RTT.
		Proxy:       nil,
		DialContext: dialer.DialContext,
	}
	handler := &proxyHTTPHandler{
		proxyFinder:   proxyFinder,
		proxySelector: proxySelector,
		httpClient: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects, but do return their contents.
				return http.ErrUseLastResponse
			},
			Jar: nil,
		},
		dialer:          dialer,
		nonProxyHandler: nonProxyHandler,
	}
	transport.Proxy = handler.lookupProxy
	return handler
}

func (h *proxyHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// EqualFold compares in place; strings.ToUpper would allocate a new
	// string on every single request.
	if strings.EqualFold(r.Method, "CONNECT") {
		h.doConnectProxy(w, r)
	} else if r.URL.IsAbs() {
		h.doHTTPProxy(w, r)
	} else if h.nonProxyHandler != nil {
		h.nonProxyHandler.ServeHTTP(w, r)
	} else {
		http.Error(w, "", http.StatusBadRequest)
	}
}

func (h *proxyHTTPHandler) lookupProxy(r *http.Request) (*url.URL, error) {
	proxies, err := h.proxyFinder.FindProxyForURL(r.URL)
	if err != nil {
		return nil, err
	}
	proxy := h.proxySelector.SelectProxy(proxies)
	// Guard at the call site (rather than inside a helper) so the variadic
	// boxing of the arguments never happens per request when logging is
	// off; a helper call would still evaluate and heap-allocate its args.
	if verbose {
		log.Printf("Proxy Lookup %q, got %q. Selected %q", r.URL, proxies, proxy)
	}
	if proxy == pac.DirectProxy {
		return nil, nil
	}
	proxyURL := &url.URL{
		Host: net.JoinHostPort(proxy.Hostname, strconv.Itoa(proxy.Port)),
	}
	if proxyAuth := r.Header.Get("Proxy-Authorization"); proxyAuth != "" {
		if u, p, ok := parseBasicAuth(proxyAuth); ok {
			proxyURL.User = url.UserPassword(u, p)
		}
	}
	return proxyURL, nil
}

func (h *proxyHTTPHandler) doConnectProxy(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := h.lookupProxy(r)
	if err != nil {
		log.Printf("HTTP Connect Proxy %q: %d %s", r.URL, http.StatusBadGateway, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Dial with the request context so a client that goes away while we
	// are still connecting does not leave a stray upstream dial burning a
	// timeout and a file descriptor for nothing.
	dialCtx := r.Context()
	var serverConn net.Conn
	if proxyURL == nil {
		serverConn, err = h.dialer.DialContext(dialCtx, "tcp", r.URL.Host)
	} else {
		serverConn, err = h.dialer.DialContext(dialCtx, "tcp", proxyURL.Host)
	}
	if err != nil {
		log.Printf("HTTP Connect Proxy %q: %d %s", r.URL, http.StatusBadGateway, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer serverConn.Close()
	setKeepAlive(serverConn)

	// handshake is the exact byte sequence to send to the client once the
	// client connection has been hijacked.
	var handshake []byte
	if proxyURL != nil {
		removeProxyHeaders(r)
		// instead of WriteProxy as this will *hopefully* deal with CONNECT correctly.
		if err = r.Write(serverConn); err != nil {
			log.Printf("HTTP Connect Proxy %q: write to upstream failed: %s", r.URL, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		// Read and validate the upstream proxy's CONNECT response before
		// committing to the tunnel. Blindly relaying bytes hides
		// authentication failures (407) and gateway errors (502) inside
		// a "successful" tunnel where they surface as opaque TLS errors.
		//
		// Bound the wait: an upstream that goes silent after accepting
		// the dial must not pin this connection forever.
		serverConn.SetReadDeadline(time.Now().Add(connectHandshakeTimeout))
		br := bufio.NewReader(serverConn)
		handshake, err = readConnectHandshake(br)
		serverConn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Printf("HTTP Connect Proxy %q: %d upstream CONNECT response: %s", r.URL, http.StatusBadGateway, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		// From here on reads from serverConn must go through br so bytes
		// the upstream already pipelined behind its handshake are not
		// lost into the relay.
		serverConn = &prefetchedConn{conn: serverConn, br: br}
	} else {
		handshake = []byte(directConnectResponse)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		err = errors.New("unable to get hijacker")
		log.Printf("HTTP Connect Proxy %q: %d %s", r.URL, http.StatusBadGateway, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("HTTP Connect Proxy %q: %d %s", r.URL, http.StatusBadGateway, err)
		return
	}
	defer clientConn.Close()

	if status := connectHandshakeStatus(handshake); status/100 != 2 {
		// The upstream proxy rejected the CONNECT (e.g. 407 auth
		// required). Relay the real status to the client instead of
		// pretending the tunnel is open; it can then react, and the
		// error surfaces immediately rather than as a TLS failure.
		clientConn.Write(handshake)
		verboseLogf("HTTP Connect Proxy %q: upstream rejected CONNECT: %s", r.URL, firstLine(handshake))
		return
	}

	setKeepAlive(clientConn)
	if _, err = clientConn.Write(handshake); err != nil {
		return
	}
	verboseLogf("HTTP Connect Proxy %q: tunnel established", r.URL)
	relay(clientConn, serverConn)
}

// readConnectHandshake consumes exactly the status line plus header block
// (up to and including the terminating blank line) from br and returns them
// verbatim so they can be forwarded to the client unchanged.
func readConnectHandshake(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			buf.Write(line)
		}
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			// Blank line terminates the header block.
			out := buf.Bytes()
			if !bytes.HasPrefix(out, []byte("HTTP/")) {
				return nil, errors.New("malformed CONNECT response status line")
			}
			return out, nil
		}
	}
}

// connectHandshakeStatus parses the status code out of a captured CONNECT
// response handshake.
func connectHandshakeStatus(handshake []byte) int {
	parts := strings.Fields(firstLine(handshake))
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return code
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(bytes.TrimRight(b[:i], "\r"))
	}
	return string(bytes.TrimRight(b, "\r"))
}

// prefetchedConn layers a bufio.Reader (holding bytes read during handshake
// parsing) over a raw connection so tunnel relays neither lose buffered
// bytes nor block on them. It deliberately exposes only the net.Conn surface
// plus CloseWrite: no WriteTo/ReadFrom/SyscallConn promotion, otherwise
// io.CopyBuffer could take the kernel splice path and bypass the buffer.
type prefetchedConn struct {
	conn net.Conn
	br   *bufio.Reader
}

func (c *prefetchedConn) Read(p []byte) (int, error)  { return c.br.Read(p) }
func (c *prefetchedConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *prefetchedConn) Close() error                { return c.conn.Close() }
func (c *prefetchedConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *prefetchedConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *prefetchedConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *prefetchedConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *prefetchedConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
func (c *prefetchedConn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.conn.Close()
}

// relay pumps bytes in both directions until both have finished.
//
// When one direction sees EOF, the write side of its peer is half-closed with
// a FIN so protocols that rely on seeing EOF (HTTP/1.0 responses, plain text
// sockets) terminate cleanly, and the opposite direction is given
// tunnelDrainTimeout to finish carrying its remaining bytes. This replaces the
// previous behaviour of arming a 10ms deadline on one socket as soon as
// either direction finished, which both truncated in-flight data and could
// leave the other direction wedged.
//
// If a direction ends with a real error (rather than EOF) both sockets are
// closed immediately, because the tunnel is then unusable.
func relay(clientConn, serverConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := tunnelBufPool.Get().(*[]byte)
		defer tunnelBufPool.Put(buf)
		if _, err := copyTunnel(clientConn, serverConn, *buf); err != nil {
			closeBoth(clientConn, serverConn)
			return
		}
		// server finished sending: tell the client no more data follows,
		// then bound how long the client may take to finish upstream.
		closeWrite(clientConn)
		clientConn.SetReadDeadline(time.Now().Add(tunnelDrainTimeout))
	}()
	go func() {
		defer wg.Done()
		buf := tunnelBufPool.Get().(*[]byte)
		defer tunnelBufPool.Put(buf)
		if _, err := copyTunnel(serverConn, clientConn, *buf); err != nil {
			closeBoth(clientConn, serverConn)
			return
		}
		closeWrite(serverConn)
		serverConn.SetReadDeadline(time.Now().Add(tunnelDrainTimeout))
	}()
	wg.Wait()
}

// copyTunnel relays src to dst, preferring the kernel splice path (true
// zero-copy, which measurably helps bulk transfers through plain TCP
// tunnels) when dst can ReadFrom a socket, then WriteTo, and falling back to
// the caller's pooled userspace buffer otherwise. This is io.Copy's
// negotiation plus a pooled fallback buffer.
func copyTunnel(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	return io.CopyBuffer(dst, src, buf)
}

func closeBoth(conns ...net.Conn) {
	for _, c := range conns {
		c.Close()
	}
}

// closeWrite half-closes the write side of a TCP connection if supported,
// falling back to a full close for connection types without CloseWrite.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// setKeepAlive enables tuned TCP keep-alive probes on c (when it is a TCP
// connection) so idle tunnels survive NAT timeouts, and a peer that vanished
// without a FIN is reclaimed after roughly Idle + Count*Interval instead of
// pinning a file descriptor forever.
func setKeepAlive(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	tcp.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     tunnelIdleKeepAlive,
		Interval: tunnelKeepAliveInterval,
		Count:    tunnelKeepAliveCount,
	})
}

func (h *proxyHTTPHandler) doHTTPProxy(w http.ResponseWriter, r *http.Request) {
	removeProxyHeaders(r)
	resp, err := h.httpClient.Do(r)
	if err != nil && resp == nil {
		log.Printf("HTTP Proxy %q: %d %s", r.URL, http.StatusBadGateway, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	wh := w.Header()
	clearHeaders(wh)
	copyHeaders(wh, resp.Header)
	w.WriteHeader(resp.StatusCode)
	buf := bodyBufPool.Get().(*[]byte)
	defer bodyBufPool.Put(buf)
	io.CopyBuffer(w, resp.Body, *buf)
}

func removeProxyHeaders(r *http.Request) {
	// this must be reset when serving a request with the client
	r.RequestURI = ""
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")
	// curl can add that, see
	// http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")
	// Connection is single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	r.Header.Del("Connection")
}

func clearHeaders(dst http.Header) {
	for k := range dst {
		dst.Del(k)
	}
}

// verbose reports whether -v was passed; it is set from main before serving
// begins. Declared here (rather than in pacproxy.go) so the handler package
// stays self-contained for tests.
var verbose bool

// verboseLogf logs only when verbose output is enabled. The guard keeps the
// variadic argument boxing and formatting off the hot path in the default
// (quiet) configuration, instead of relying on log.SetOutput(io.Discard)
// which still pays for formatting each call.
func verboseLogf(format string, v ...any) {
	if verbose {
		log.Printf(format, v...)
	}
}

// copyHeaders copies upstream response headers to the client response,
// dropping the headers that describe only the upstream hop (RFC 7230 6.1).
// Forwarding e.g. an upstream "Connection: close" would make the Go server
// tear down the client's keep-alive session even though the downstream
// connection is perfectly reusable: exactly the small-connection reliability
// bug this proxy is supposed to avoid.
func copyHeaders(dst, src http.Header) {
	dynamic := connectionTokens(src)
	for k, vs := range src {
		if isHopByHopResponseHeader(k) {
			continue
		}
		skip := false
		for _, d := range dynamic {
			if d == k {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isHopByHopResponseHeader(k string) bool {
	switch k {
	case "Connection", "Proxy-Connection", "Keep-Alive",
		"Transfer-Encoding", "Te", "Trailer", "Upgrade":
		return true
	}
	return false
}

// connectionTokens returns the canonical header names a Connection header
// declares as hop-by-hop for this hop (usually empty, so usually free).
func connectionTokens(src http.Header) []string {
	vals, ok := src["Connection"]
	if !ok {
		return nil
	}
	var out []string
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, http.CanonicalHeaderKey(tok))
			}
		}
	}
	return out
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}
