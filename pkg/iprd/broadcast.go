package iprd

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/goccy/go-json"
)

const (
	TCPCommandSubscribe = "iprd_subscribe"
	TCPCommandStatus    = "iprd_status"
)

// TCPCommand describes a TCP command.
type TCPCommand struct {
	Command   string `json:"command"`
	RequestID string `json:"requestID,omitempty"`
}

// TCPResponse is the response envelope for one-shot TCP commands.
type TCPResponse struct {
	Type      string         `json:"type"`
	RequestID string         `json:"requestID,omitempty"`
	Timestamp int64          `json:"timestamp"`
	Status    *ManagerStatus `json:"status,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// StatusProvider supplies the current listener manager status.
type StatusProvider interface {
	Status() ManagerStatus
}

type IPRBroadcast struct {
	logger         Logger
	listener       net.Listener
	counter        uint64
	mu             sync.RWMutex
	clients        map[uint64]net.Conn
	statusProvider StatusProvider
	Msgs           chan []byte
	Errs           chan error
}

// NewBroadcaster returns a new IPRBroadcast at specified port. bind is the local
// IP address to listen on; an empty bind binds all interfaces.
func NewBroadcaster(logger Logger, bind string, port int) (*IPRBroadcast, error) {
	if logger == nil {
		logger = NewLogger()
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
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

// SetStatusProvider configures the provider used by the iprd_status command.
func (b *IPRBroadcast) SetStatusProvider(provider StatusProvider) {
	b.mu.Lock()
	b.statusProvider = provider
	b.mu.Unlock()
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

func writeTCPResponse(conn net.Conn, response TCPResponse) error {
	msg, err := json.Marshal(response)
	if err != nil {
		return err
	}
	msg = append(msg, '\n')
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err = conn.Write(msg)
	return err
}

func (b *IPRBroadcast) statusResponse(cmd TCPCommand) TCPResponse {
	response := TCPResponse{
		Type:      TCPCommandStatus,
		RequestID: cmd.RequestID,
		Timestamp: time.Now().Unix(),
	}
	b.mu.RLock()
	provider := b.statusProvider
	b.mu.RUnlock()
	if provider == nil {
		response.Error = "status unavailable"
		return response
	}
	status := provider.Status()
	response.Status = &status
	return response
}

func (b *IPRBroadcast) handleConnection(conn net.Conn) {
	id := b.incrementCounter()
	defer func() {
		b.mu.Lock()
		delete(b.clients, id)
		b.mu.Unlock()
		conn.Close()
	}()

	// Enable TCP keepalive so dead peers are detected even when no data is
	// flowing, rather than lingering as half-open sockets.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientSubscribed := false
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if clientSubscribed {
			continue
		}

		var cmd TCPCommand
		if err := json.Unmarshal(scanner.Bytes(), &cmd); err != nil {
			continue
		}

		switch cmd.Command {
		case TCPCommandSubscribe:
			conn.SetReadDeadline(time.Time{})
			clientSubscribed = true
			b.mu.Lock()
			b.clients[id] = conn
			b.mu.Unlock()
			b.logger.Info(fmt.Sprintf("accepted new connection from: %s", conn.RemoteAddr().String()))
		case TCPCommandStatus:
			if err := writeTCPResponse(conn, b.statusResponse(cmd)); err != nil {
				b.logger.Error(fmt.Errorf("status response to %s: %w", conn.RemoteAddr(), err))
			}
			return
		default:
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			b.logger.Error(fmt.Errorf("scanner error from %s: %w", conn.RemoteAddr(), err))
		}
	} else if clientSubscribed {
		b.logger.Info(fmt.Sprintf("client gracefully disconnected: %s", conn.RemoteAddr()))
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
		go b.handleConnection(conn)
	}
}
