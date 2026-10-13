package ingestion

import (
	"bufio"
	"context"
	"fmt"
	"net"
)

// TCPReceiver listens for incoming syslog messages over TCP.
type TCPReceiver struct {
	addr string
	out  chan RawLog
}

// NewTCPReceiver creates a new TCP syslog receiver.
func NewTCPReceiver(addr string, bufferSize int) *TCPReceiver {
	return &TCPReceiver{
		addr: addr,
		out:  make(chan RawLog, bufferSize),
	}
}

// Channel returns the receive-only channel yielding raw logs.
func (r *TCPReceiver) Channel() <-chan RawLog {
	return r.out
}

// Start begins listening on the configured TCP address.
func (r *TCPReceiver) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.addr)
	if err != nil {
		return fmt.Errorf("listening on tcp: %w", err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accepting tcp connection: %w", err)
			}
		}

		go r.handleConn(ctx, conn)
	}
}

func (r *TCPReceiver) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		case r.out <- RawLog{Data: scanner.Text(), RemoteIP: host}:
		default:
		}
	}
}
