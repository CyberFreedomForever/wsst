// Package socks implements the server side of the SOCKS5 protocol (RFC 1928).
// Only the CONNECT command without authentication is supported.
package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	version5   = 0x05
	cmdConnect = 0x01
	authNone   = 0x00
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess = 0x00
	repFailure = 0x01
)

// Request holds the parsed CONNECT destination.
type Request struct {
	Addr string // host or IP
	Port uint16
}

// Target returns the "host:port" string ready for net.Dial.
func (r *Request) Target() string {
	return fmt.Sprintf("%s:%d", r.Addr, r.Port)
}

// Handshake performs the full SOCKS5 negotiation and returns the CONNECT request.
// The caller must send a Reply after establishing the upstream connection.
func Handshake(conn net.Conn) (*Request, error) {
	// ── Method negotiation ──────────────────────────────────────────────────
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != version5 {
		return nil, fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("read methods: %w", err)
	}
	// Advertise "no authentication required"
	if _, err := conn.Write([]byte{version5, authNone}); err != nil {
		return nil, fmt.Errorf("write method select: %w", err)
	}

	// ── Request ─────────────────────────────────────────────────────────────
	fixed := make([]byte, 4)
	if _, err := io.ReadFull(conn, fixed); err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	if fixed[1] != cmdConnect {
		// Tell client we don't support this command
		conn.Write([]byte{version5, 0x07, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("unsupported command 0x%02x", fixed[1])
	}

	var host string
	switch fixed[3] {
	case atypIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return nil, err
		}
		host = net.IP(raw).String()

	case atypIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return nil, err
		}
		host = net.IP(raw).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		name := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return nil, err
		}
		host = string(name)

	default:
		return nil, fmt.Errorf("unknown address type 0x%02x", fixed[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}

	return &Request{
		Addr: host,
		Port: binary.BigEndian.Uint16(portBuf),
	}, nil
}

// Reply sends the SOCKS5 response. Call with success=true after the upstream
// connection is established, or success=false on failure.
func Reply(conn net.Conn, success bool) error {
	code := byte(repSuccess)
	if !success {
		code = repFailure
	}
	// BND.ADDR = 0.0.0.0, BND.PORT = 0 (we don't bind on client's behalf)
	_, err := conn.Write([]byte{version5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
