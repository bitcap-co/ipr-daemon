// https://github.com/magicpool-co/pool/blob/dev/cmd/proxy/server.go
package iprd

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/goccy/go-json"
)

type tcpBroadcaster struct {
	logger   *IPRLogger
	listener net.Listener
	counter  uint64
	mu       sync.RWMutex
	clients  map[uint64]net.Conn
	Msgs     chan []byte
	Errs     chan error
}

// IPRTcpCommand describes the tcp message command format {"command": "COMMAND"}
type IPRTcpCommand struct {
	Command string `json:"command"`
}

// NewBroadcaster returns a new tcpBroadcaster at specified port.
func NewBroadcaster(port int) (*tcpBroadcaster, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	b := &tcpBroadcaster{
		logger:   NewLogger(),
		listener: listener,
		clients:  make(map[uint64]net.Conn),
		Msgs:     make(chan []byte),
		Errs:     make(chan error),
	}
	return b, nil
}

func (b *tcpBroadcaster) incrementCounter() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.counter++
	if b.counter == math.MaxUint64 {
		b.counter = 0
	}
	return b.counter
}

func (b *tcpBroadcaster) broadcast(msg []byte) []error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	errs := make([]error, 0)
	for id, conn := range b.clients {
		if _, err := conn.Write(append(msg, '\n')); err != nil {
			// close and remove client on error
			conn.Close()
			delete(b.clients, id)
			errs = append(errs, err)
		}
	}

	return errs
}

// Listen accepts incoming clients and subscribes them for broadcasted messages.
func (b *tcpBroadcaster) Listen() {
	go func() {
		for {
			select {
			case msg := <-b.Msgs:
				errs := b.broadcast(msg)
				for _, err := range errs {
					if err != nil {
						b.Errs <- err
					}
				}
			}
		}
	}()
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			b.Errs <- err
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

			conn.SetReadDeadline(time.Now().Add(time.Second * 10))
			clientSubscribed := false
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				if clientSubscribed {
					continue
				}
				msg := scanner.Bytes()
				var cmd IPRTcpCommand
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
		}()
	}
}
