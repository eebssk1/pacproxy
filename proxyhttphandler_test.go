package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/williambailey/pacproxy/pac"
)

type directProxyFinder struct{}

func (f *directProxyFinder) FindProxyForURL(in *url.URL) (pac.Proxies, error) {
	return pac.Proxies{pac.DirectProxy}, nil
}

type fixedProxyFinder struct {
	proxy pac.Proxy
}

func (f *fixedProxyFinder) FindProxyForURL(in *url.URL) (pac.Proxies, error) {
	return pac.Proxies{f.proxy}, nil
}

func newTestHandler(finder pac.ProxyFinder) *proxyHTTPHandler {
	return newProxyHTTPHandler(finder, &pac.FirstItemSelector{}, nil)
}

func TestConnectDirectClosesFDs(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer target.Close()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	if string(body) != "hello" {
		t.Errorf("expected body %q, got %q", "hello", string(body))
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestConnectViaUpstreamProxyClosesFDs(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proxied"))
	}))
	defer target.Close()

	upstream := httptest.NewServer(newTestHandler(&directProxyFinder{}))
	defer upstream.Close()

	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	handler := newTestHandler(&fixedProxyFinder{
		proxy: pac.Proxy{Hostname: upstreamHost, Port: mustAtoi(upstreamPort)},
	})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	if string(body) != "proxied" {
		t.Errorf("expected body %q, got %q", "proxied", string(body))
	}
}

func TestConnectTunnelClosesOnServerDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverClosed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
		close(serverClosed)
	}()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	connectReq := "CONNECT " + listener.Addr().String() + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\n\r\n"
	conn.Write([]byte(connectReq))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	if response[:12] != "HTTP/1.0 200" {
		t.Fatalf("expected 200, got %q", response)
	}

	select {
	case <-serverClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("server accept timed out")
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after server disconnect")
	}
}

func TestConnectTunnelClosesOnClientDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConnClosed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.Copy(io.Discard, conn)
		close(serverConnClosed)
	}()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	connectReq := "CONNECT " + listener.Addr().String() + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\n\r\n"
	conn.Write([]byte(connectReq))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	if response[:12] != "HTTP/1.0 200" {
		t.Fatalf("expected 200, got %q", response)
	}

	conn.Close()

	select {
	case <-serverConnClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("server-side connection was not closed after client disconnect")
	}
}

func TestHTTPProxyForward(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("forwarded"))
	}))
	defer target.Close()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "forwarded" {
		t.Errorf("expected body %q, got %q", "forwarded", string(body))
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPProxyStripsHopByHopHeaders(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Connection") != "" {
			t.Error("Proxy-Connection header was not stripped")
		}
		if r.Header.Get("Connection") != "" {
			t.Error("Connection header was not stripped")
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	req, _ := http.NewRequest("GET", target.URL, nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Connection", "keep-alive")

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
}

func TestConnectDialFailureReturns502(t *testing.T) {
	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	connectReq := "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
	conn.Write([]byte(connectReq))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	response := string(buf[:n])
	if response[:12] != "HTTP/1.1 502" {
		t.Errorf("expected 502, got %q", response)
	}
}

func TestReadConnectHandshakeCapturesStatusAndHeaders(t *testing.T) {
	raw := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\ntrailing tunnel bytes"
	br := bufio.NewReader(strings.NewReader(raw))
	hs, err := readConnectHandshake(br)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(hs), "HTTP/1.1 407") {
		t.Fatalf("handshake missing status line: %q", hs)
	}
	if !strings.Contains(string(hs), "Proxy-Authenticate") {
		t.Fatalf("handshake dropped headers: %q", hs)
	}
	if strings.Contains(string(hs), "trailing") {
		t.Fatalf("handshake consumed tunnel bytes: %q", hs)
	}
	if connectHandshakeStatus(hs) != 407 {
		t.Fatalf("status parse: got %d want 407", connectHandshakeStatus(hs))
	}
	// Buffered remainder must still hold the tunnel payload.
	rest, _ := io.ReadAll(br)
	if string(rest) != "trailing tunnel bytes" {
		t.Fatalf("buffered payload lost: %q", rest)
	}
}

func TestConnectUpstreamRejectionSurfacesToClient(t *testing.T) {
	// A fake upstream proxy that rejects CONNECT with 407.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != "CONNECT" {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
	}()

	upHost, upPort, _ := net.SplitHostPort(upstream.Addr().String())
	handler := newTestHandler(&fixedProxyFinder{
		proxy: pac.Proxy{Hostname: upHost, Port: mustAtoi(upPort)},
	})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no response relayed: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 407") {
		t.Fatalf("expected upstream 407 relayed to client, got %q", line)
	}
}

func TestConnectDirectSends200ThenRelays(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64KiB, > tunnel buffer
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		conn.Write(payload)
		// Close sends the FIN the client should observe through the relay.
		conn.Close()
	}()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("CONNECT " + target.Addr().String() + " HTTP/1.1\r\nHost: " + target.Addr().String() + "\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.0 200") {
		t.Fatalf("expected 200 handshake, got %q err %v", line, err)
	}
	// skip the blank line
	if _, err = br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(payload))
	}
}

func TestHTTPProxyLargeBodyIntegrity(t *testing.T) {
	body := make([]byte, 4<<20) // 4 MiB
	rand.Read(body)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(body)
	}))
	defer target.Close()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("downloaded %d bytes, mismatch=%v", len(got), !bytes.Equal(got, body))
	}
}

// TestHTTPProxyUpstreamConnectionCloseKeepsClientAlive guards the hop-by-hop
// strip: an upstream answering "Connection: close" must NOT make the proxy
// tear down the client's keep-alive connection, otherwise every small
// long-lived client connection dies on the first upstream hiccup.
func TestHTTPProxyUpstreamConnectionCloseKeepsClientAlive(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				// upstream says close, then hangs up
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"))
			}(conn)
		}
	}()

	handler := newTestHandler(&directProxyFinder{})
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	originURL := "http://" + origin.Addr().String() + "/"
	for i := 0; i < 2; i++ {
		resp, err := client.Get(originURL)
		if err != nil {
			t.Fatalf("request %d failed (client connection killed by upstream Connection: close): %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hi" {
			t.Fatalf("request %d body=%q", i+1, body)
		}
		if resp.Header.Get("Connection") == "close" {
			t.Fatalf("upstream Connection header leaked through to the client")
		}
	}
}

func TestConnectHandshakeStatus(t *testing.T) {
	cases := map[string]int{
		"HTTP/1.0 200 OK\r\n\r\n":                    200,
		"HTTP/1.1 407 Proxy Authentication Required": 407,
		"HTTP/1.1 502 Bad Gateway\r\n":               502,
		"garbage":                                    0,
	}
	for in, want := range cases {
		if got := connectHandshakeStatus([]byte(in)); got != want {
			t.Errorf("connectHandshakeStatus(%q)=%d want %d", in, got, want)
		}
	}
}

func TestCloseWritePrefersHalfClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	// net.Pipe has no CloseWrite; fallback full-close must unblock server reads.
	go func() {
		buf := make([]byte, 8)
		server.Read(buf)
	}()
	closeWrite(client)
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 8)); err == nil {
		t.Fatal("expected read error after fallback close")
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
