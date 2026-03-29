// wsst — WebSocket Secure Tunnel
//
// Usage:
//
//	wsst server  [flags]   — run on VPS2 (HTTP/2 + TLS 1.3 + WSS endpoint)
//	wsst gateway [flags]   — run on VPS1 (SOCKS5 listener + WSS client)
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CyberFreedomForever/wsst/internal/mux"
	"github.com/CyberFreedomForever/wsst/internal/socks"
	"nhooyr.io/websocket"
	"golang.org/x/net/http2"
)

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "gateway":
		runGateway(os.Args[2:])
	case "version":
		fmt.Println("wsst v1.0.0")
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `wsst — WebSocket Secure Tunnel

Usage:
  wsst server  [flags]
  wsst gateway [flags]

Server flags (VPS2 — exit node):
  -server  wss://host/tunnel   used to extract the /tunnel path; only this path
                               accepts WebSocket upgrades (default: /tunnel)
  -addr    :443                listen address (default :443)
  -cert    /path/fullchain.pem TLS certificate (Let's Encrypt)
  -key     /path/privkey.pem   TLS private key
  -secret  <token>             shared secret sent in X-Tunnel-Secret header

Gateway flags (VPS1 — SOCKS5 gateway):
  -server  wss://host/path     WSS URL of the server (required)
  -socks   :1080               SOCKS5 listen address (default :1080)
  -secret  <token>             shared secret (must match server)
  -insecure                    skip TLS certificate verification (dev only)
`)
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVER (VPS2)
// ─────────────────────────────────────────────────────────────────────────────

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	serverURL := fs.String("server", "", "wss://host/path — used to derive the tunnel path (default /tunnel)")
	addr      := fs.String("addr", ":443", "listen address")
	certFile  := fs.String("cert", "/etc/letsencrypt/live/example.com/fullchain.pem", "TLS certificate")
	keyFile   := fs.String("key", "/etc/letsencrypt/live/example.com/privkey.pem", "TLS private key")
	secret    := fs.String("secret", "", "shared tunnel secret (required)")
	fs.Parse(args)

	// Derive the tunnel path from -server URL, or default to /tunnel
	tunnelPath := "/tunnel"
	if *serverURL != "" {
		tunnelPath = pathFromWSS(*serverURL)
	}

	if *secret == "" {
		log.Fatal("[server] -secret is required")
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("[server] TLS: %v", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(tunnelPath, makeServerHandler(*secret))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Any path other than the tunnel path returns a plain 200
		// (reduces fingerprinting)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // tunnel connections are long-lived
		IdleTimeout:  120 * time.Second,
	}

	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxHandlers:          0,
		MaxConcurrentStreams: 250,
	}); err != nil {
		log.Fatalf("[server] http2: %v", err)
	}

	log.Printf("[server] listening on %s  tunnel path: %s  TLS 1.3 + HTTP/2", *addr, tunnelPath)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("[server] %v", err)
	}
}

// makeServerHandler returns the HTTP handler for the WSS tunnel endpoint.
func makeServerHandler(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate via header
		if r.Header.Get("X-Tunnel-Secret") != secret {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionContextTakeover,
		})
		if err != nil {
			log.Printf("[server] ws accept: %v", err)
			return
		}
		defer wsConn.Close(websocket.StatusNormalClosure, "bye")

		log.Printf("[server] tunnel up from %s", r.RemoteAddr)

		sess := mux.NewSession(r.Context(), wsConn, true)
		defer sess.Close()

		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				log.Printf("[server] accept stream: %v", err)
				return
			}
			go serverHandleStream(stream)
		}
	}
}

// serverHandleStream reads the target address from the stream, dials it,
// then pipes data in both directions.
func serverHandleStream(stream *mux.Stream) {
	defer stream.Close()

	// First message: "host:port\n"
	target, err := readLine(stream)
	if err != nil || target == "" {
		log.Printf("[server] read target: %v", err)
		return
	}

	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		DualStack: true, // IPv4 + IPv6
	}
	upstream, err := dialer.DialContext(context.Background(), "tcp", target)
	if err != nil {
		log.Printf("[server] dial %s: %v", target, err)
		return
	}
	defer upstream.Close()

	log.Printf("[server] → %s", target)
	pipe(stream, upstream)
}

// ─────────────────────────────────────────────────────────────────────────────
// GATEWAY (VPS1)
// ─────────────────────────────────────────────────────────────────────────────

// gatewayState holds the single live WSS session (replaced on reconnect).
type gatewayState struct {
	mu   sync.RWMutex
	sess *mux.Session
}

func (g *gatewayState) get() *mux.Session {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.sess
}

func (g *gatewayState) set(s *mux.Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sess = s
}

func runGateway(args []string) {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	serverURL  := fs.String("server", "", "wss://host/path  WSS server URL (required)")
	socksAddr  := fs.String("socks", ":1080", "SOCKS5 listen address")
	secret     := fs.String("secret", "", "shared tunnel secret (required)")
	insecure   := fs.Bool("insecure", false, "skip TLS certificate verification (dev only)")
	fs.Parse(args)

	if *serverURL == "" {
		log.Fatal("[gateway] -server is required")
	}
	if *secret == "" {
		log.Fatal("[gateway] -secret is required")
	}

	state := &gatewayState{}

	// Maintain a persistent WSS connection to the server
	go maintainTunnel(state, *serverURL, *secret, *insecure)

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("[gateway] socks listen: %v", err)
	}
	log.Printf("[gateway] SOCKS5 on %s  →  %s", *socksAddr, *serverURL)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[gateway] accept: %v", err)
			continue
		}
		go gatewayHandleSocks(conn, state)
	}
}

// maintainTunnel keeps the WSS session alive, reconnecting on failure.
func maintainTunnel(state *gatewayState, serverURL, secret string, insecure bool) {
	backoff := time.Second
	for {
		sess, err := dialTunnel(serverURL, secret, insecure)
		if err != nil {
			log.Printf("[gateway] connect failed: %v — retry in %s", err, backoff)
			time.Sleep(backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second // reset on success
		state.set(sess)
		log.Printf("[gateway] tunnel connected to %s", serverURL)

		// Block until the session dies
		<-sess.Context()
		state.set(nil)
		log.Printf("[gateway] tunnel lost, reconnecting…")
		time.Sleep(2 * time.Second)
	}
}

// dialTunnel establishes a single WSS connection and returns the Session.
func dialTunnel(serverURL, secret string, insecure bool) (*mux.Session, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecure,
	}

	// HTTP/2 transport — WebSocket runs over HTTP/2 CONNECT (RFC 8441)
	transport := &http2.Transport{
		TLSClientConfig: tlsCfg,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	wsConn, _, err := websocket.Dial(ctx, serverURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport},
		HTTPHeader: http.Header{
			"X-Tunnel-Secret": []string{secret},
		},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		return nil, err
	}

	// Use a background context for the session lifetime
	sess := mux.NewSession(context.Background(), wsConn, false)
	return sess, nil
}

// gatewayHandleSocks handles one SOCKS5 client connection.
func gatewayHandleSocks(conn net.Conn, state *gatewayState) {
	defer conn.Close()

	req, err := socks.Handshake(conn)
	if err != nil {
		log.Printf("[gateway] socks handshake: %v", err)
		return
	}
	target := req.Target()

	sess := state.get()
	if sess == nil {
		log.Printf("[gateway] no tunnel for %s — tunnel is down", target)
		socks.Reply(conn, false)
		return
	}

	stream, err := sess.OpenStream()
	if err != nil {
		log.Printf("[gateway] open stream: %v", err)
		socks.Reply(conn, false)
		return
	}

	// Send target address as first line
	if _, err := fmt.Fprintf(stream, "%s\n", target); err != nil {
		log.Printf("[gateway] send target: %v", err)
		socks.Reply(conn, false)
		stream.Close()
		return
	}

	socks.Reply(conn, true)
	log.Printf("[gateway] %s → tunnel → %s", conn.RemoteAddr(), target)
	pipe(stream, conn)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// pipe copies data between a and b until either side closes.
func pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(a, b); a.Close() }()
	go func() { defer wg.Done(); io.Copy(b, a); b.Close() }()
	wg.Wait()
}

// readLine reads bytes from r until '\n' or EOF.
func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimSpace(sb.String()), nil
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			return strings.TrimSpace(sb.String()), err
		}
	}
}

// pathFromWSS extracts the path component from a wss:// URL.
// "wss://host:443/tunnel" → "/tunnel"
func pathFromWSS(u string) string {
	// Strip scheme
	s := strings.TrimPrefix(u, "wss://")
	s = strings.TrimPrefix(s, "ws://")
	// Find first slash after host
	idx := strings.Index(s, "/")
	if idx < 0 {
		return "/tunnel"
	}
	p := s[idx:]
	// Strip query/fragment
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/tunnel"
	}
	return p
}
