// Package mux implements a lightweight stream multiplexer over a WebSocket connection.
//
// Frame format: [4 stream_id][4 payload_len][payload]
// A frame with payload_len=0 is a FIN (stream close).
package mux

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

const (
	frameHeaderSize = 8 // stream_id(4) + length(4)
	maxChunk        = 32 * 1024
	streamBufSize   = 512
)

// Session multiplexes many logical streams over one WebSocket.
type Session struct {
	conn    *websocket.Conn
	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  atomic.Uint32
	accept  chan *Stream
	ctx     context.Context
	cancel  context.CancelFunc
	writeMu sync.Mutex // serialize writes to conn
}

// Stream is a logical bidirectional channel inside a Session.
// It implements net.Conn (deadlines are no-ops for simplicity).
type Stream struct {
	id      uint32
	session *Session
	buf     chan []byte
	once    sync.Once
	done    chan struct{}
}

// NewSession wraps an accepted or dialed WebSocket connection.
// isServer: server uses even stream IDs, client uses odd ones (avoids collisions).
func NewSession(ctx context.Context, conn *websocket.Conn, isServer bool) *Session {
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{
		conn:    conn,
		streams: make(map[uint32]*Stream),
		accept:  make(chan *Stream, 128),
		ctx:     ctx,
		cancel:  cancel,
	}
	if isServer {
		s.nextID.Store(2)
	} else {
		s.nextID.Store(1)
	}
	go s.readLoop()
	return s
}

// OpenStream creates a new outbound logical stream.
func (s *Session) OpenStream() (*Stream, error) {
	select {
	case <-s.ctx.Done():
		return nil, fmt.Errorf("session closed")
	default:
	}
	id := s.nextID.Add(2) - 2
	st := newStream(id, s)
	s.mu.Lock()
	s.streams[id] = st
	s.mu.Unlock()
	return st, nil
}

// AcceptStream blocks until an inbound stream arrives or the session closes.
func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.ctx.Done():
		return nil, fmt.Errorf("session closed")
	}
}

// Close terminates the session and all its streams.
func (s *Session) Close() { s.cancel() }

// Context returns a channel that is closed when the session ends.
// Useful for waiting on tunnel death without polling.
func (s *Session) Context() <-chan struct{} { return s.ctx.Done() }

func (s *Session) readLoop() {
	defer s.cancel()
	for {
		_, data, err := s.conn.Read(s.ctx)
		if err != nil {
			log.Printf("[mux] read: %v", err)
			return
		}
		if len(data) < frameHeaderSize {
			continue
		}
		id := binary.BigEndian.Uint32(data[0:4])
		payload := data[frameHeaderSize:]

		s.mu.Lock()
		st, ok := s.streams[id]
		if !ok {
			st = newStream(id, s)
			s.streams[id] = st
			s.mu.Unlock()
			select {
			case s.accept <- st:
			default:
				log.Printf("[mux] accept channel full, dropping stream %d", id)
			}
		} else {
			s.mu.Unlock()
		}

		if len(payload) == 0 {
			// FIN — remote closed
			st.closeDone()
			s.mu.Lock()
			delete(s.streams, id)
			s.mu.Unlock()
			continue
		}

		chunk := make([]byte, len(payload))
		copy(chunk, payload)
		select {
		case st.buf <- chunk:
		case <-st.done:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Session) writeFrame(id uint32, data []byte) error {
	hdr := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], id)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(data)))
	frame := append(hdr, data...)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.Write(s.ctx, websocket.MessageBinary, frame)
}

// ── Stream ──────────────────────────────────────────────────────────────────

func newStream(id uint32, s *Session) *Stream {
	return &Stream{
		id:      id,
		session: s,
		buf:     make(chan []byte, streamBufSize),
		done:    make(chan struct{}),
	}
}

func (st *Stream) closeDone() {
	st.once.Do(func() { close(st.done) })
}

// Read implements net.Conn.
func (st *Stream) Read(p []byte) (int, error) {
	select {
	case chunk, ok := <-st.buf:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		return n, nil
	case <-st.done:
		// drain any remaining data
		select {
		case chunk := <-st.buf:
			n := copy(p, chunk)
			return n, nil
		default:
			return 0, io.EOF
		}
	case <-st.session.ctx.Done():
		return 0, net.ErrClosed
	}
}

// Write implements net.Conn.
func (st *Stream) Write(p []byte) (int, error) {
	sent := 0
	for sent < len(p) {
		end := sent + maxChunk
		if end > len(p) {
			end = len(p)
		}
		if err := st.session.writeFrame(st.id, p[sent:end]); err != nil {
			return sent, err
		}
		sent = end
	}
	return sent, nil
}

// Close sends a FIN frame and removes the stream from the session.
func (st *Stream) Close() error {
	st.once.Do(func() {
		_ = st.session.writeFrame(st.id, nil)
		close(st.done)
		st.session.mu.Lock()
		delete(st.session.streams, st.id)
		st.session.mu.Unlock()
	})
	return nil
}

func (st *Stream) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (st *Stream) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (st *Stream) SetDeadline(_ time.Time) error      { return nil }
func (st *Stream) SetReadDeadline(_ time.Time) error  { return nil }
func (st *Stream) SetWriteDeadline(_ time.Time) error { return nil }

var _ net.Conn = (*Stream)(nil)
