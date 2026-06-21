package iprd

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"sync"
	"time"

	"github.com/goccy/go-json"
)

// TCPCommand describes a tcp command.
type TCPCommand struct {
	Command string `json:"command"`
}

type IPRBroadcast struct {
	logger   *IPRLogger
	listener net.Listener
	counter  uint64
	mu       sync.RWMutex
	clients  map[uint64]net.Conn
	Msgs     chan []byte
	Errs     chan error
}

// NewBroadcaster returns a new IPRBroadcast at specified port.
func NewBroadcaster(logger *IPRLogger, port int) (*IPRBroadcast, error) {
	if logger == nil {
		logger = NewLogger()
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	b := &IPRBroadcast{
		logger:   logger,
		listener: listener,
		clients:  make(map[uint64]net.Conn),
		Msgs:     make(chan []byte),
		Errs:     make(chan error, 64),
	}
	return b, nil
}

func (b *IPRBroadcast) incrementCounter() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.counter++
	if b.counter == math.MaxUint64 {
		b.counter = 0
	}
	return b.counter
}

// writeTimeout bounds a single client write so a slow or half-open
// connection cannot stall delivery to every other client.
const writeTimeout = 5 * time.Second

func (b *IPRBroadcast) broadcast(msg []byte) {
	// Build the payload once. msg is owned by the channel sender, so we copy
	// into a fresh buffer rather than appending in place.
	payload := make([]byte, len(msg)+1)
	copy(payload, msg)
	payload[len(msg)] = '\n'

	// Snapshot the client set so we don't hold the lock across blocking
	// writes (which would also block new subscriptions).
	b.mu.RLock()
	conns := make(map[uint64]net.Conn, len(b.clients))
	maps.Copy(conns, b.clients)
	b.mu.RUnlock()

	for id, conn := range conns {
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := conn.Write(payload); err != nil {
			// Close and reap the client on any write error.
			b.logger.Error(fmt.Errorf("dropping client %s: %w", conn.RemoteAddr(), err))
			conn.Close()
			b.mu.Lock()
			delete(b.clients, id)
			b.mu.Unlock()
		}
	}
}

// Listen accepts incoming clients and subscribes them for broadcasted messages.
func (b *IPRBroadcast) Listen() {
	go func() {
		for msg := range b.Msgs {
			// broadcast logs and reaps failed clients itself; it never
			// blocks on b.Errs, so the producer can't deadlock against it.
			b.broadcast(msg)
		}
	}()
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			// Non-blocking: never wedge the accept loop if nobody is
			// draining Errs at this instant.
			select {
			case b.Errs <- err:
			default:
				b.logger.Error(err)
			}
		}

		if conn == nil {
			continue
		}
		go func() {
			id := b.incrementCounter()
			defer func() {
				b.mu.Lock()
				defer b.mu.Unlock()
				delete(b.clients, id)
				conn.Close()
			}()

			// Enable TCP keepalive so dead peers are detected even when no
			// data is flowing, rather than lingering as half-open sockets.
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			conn.SetReadDeadline(time.Now().Add(time.Second * 10))
			clientSubscribed := false
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				if clientSubscribed {
					continue
				}
				msg := scanner.Bytes()
				var cmd TCPCommand
				if err := json.Unmarshal(msg, &cmd); err == nil {
					if cmd.Command == "iprd_subscribe" {
						conn.SetReadDeadline(time.Time{})
						clientSubscribed = true
						b.mu.Lock()
						b.clients[id] = conn
						b.mu.Unlock()
						b.logger.Info(fmt.Sprintf("accepted new connection from: %s", conn.RemoteAddr().String()))
					}
				}
			}
			if err := scanner.Err(); err != nil {
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					b.logger.Error(fmt.Errorf("scanner error from %s: %w", conn.RemoteAddr(), err))
				}
			}
		}()
	}
}
