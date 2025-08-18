package iprd

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
)

// https://github.com/magicpool-co/pool/blob/dev/cmd/proxy/server.go
type tcpBroadcaster struct {
	logger   *IPRLogger
	listener net.Listener
	counter  uint64
	mu       sync.RWMutex
	clients  map[uint64]net.Conn
	Msgs     chan []byte
	Errs     chan error
}

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
			// remove dead clients
			if strings.Contains(err.Error(), "broken pipe") {
				conn.Close()
				delete(b.clients, id)
			}
			errs = append(errs, err)
		}
	}

	return errs
}

func (b *tcpBroadcaster) Listen() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			b.Errs <- err
		}

		if conn == nil {
			continue
		}
		b.logger.Info(fmt.Sprintf("accepted new connection from: %s", conn.RemoteAddr().String()))
		go func() {
			id := b.incrementCounter()
			defer func() {
				b.mu.Lock()
				defer b.mu.Unlock()
				delete(b.clients, id)
				conn.Close()
			}()

			b.mu.Lock()
			b.clients[id] = conn
			b.mu.Unlock()

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
	}
}
