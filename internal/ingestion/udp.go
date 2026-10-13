package ingestion

import (
	"context"
	"fmt"
	"net"
)

// RawLog encapsulates a received packet payload and the sender's network address.
type RawLog struct {
	Data     string
	RemoteIP string
}

// Receiver manages a UDP socket listener for syslog datagrams.
type Receiver struct {
	addr string
	out  chan RawLog
	conn *net.UDPConn
}

// Reciever is a type alias for Receiver.
type Reciever = Receiver

// NewReceiver creates a new UDP syslog listener on the specified address.
func NewReceiver(addr string, bufferSize int) *Receiver {
	return &Receiver{
		addr: addr,
		out:  make(chan RawLog, bufferSize),
	}
}

// NewReciever is an alias for NewReceiver.
func NewReciever(addr string, bufferSize int) *Receiver {
	return NewReceiver(addr, bufferSize)
}

// Channel returns the receive-only channel yielding incoming raw logs.
func (r *Receiver) Channel() <-chan RawLog {
	return r.out
}

// Start begins listening on the UDP port. It terminates when ctx is cancelled.
func (r *Receiver) Start(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", r.addr)
	if err != nil {
		return fmt.Errorf("resolving udp address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listening on udp: %w", err)
	}
	r.conn = conn

	go func() {
		<-ctx.Done()
		r.conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := r.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				close(r.out)
				return nil
			default:
				return fmt.Errorf("reading from udp: %w", err)
			}
		}

		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			host = remoteAddr.String()
		}

		select {
		case r.out <- RawLog{Data: string(buf[:n]), RemoteIP: host}:
		default:
		}
	}
}
