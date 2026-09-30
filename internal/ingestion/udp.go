package ingestion

import (
	"context"
	"fmt"
	"net"
)

// Encapsulation of Sender's IP addr and recieved packet
type RawLog struct {
	Data     string
	RemoteIP string
}

// UDP socket listener
type Reciever struct {
	addr string
	out  chan RawLog
	conn *net.UDPConn
}

// Creates a new UDP syslog listener on the specified address
func NewReciever(addr string, bufferSize int) *Reciever {
	return &Reciever{
		addr: addr,
		out:  make(chan RawLog, bufferSize),
	}
}

// Returns the recieve-only channel yielding incoming raw logs
func (r *Reciever) Channel() <-chan RawLog {
	return r.out
}

func (r *Reciever) Start(ctx context.Context) error {
	udpaddr, err := net.ResolveUDPAddr("udp", r.addr)
	if err != nil {
		return fmt.Errorf("resolving udp address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		return fmt.Errorf("listening to udp: %w", err)
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
			// Check if closed intentionally
			select {
			case <-ctx.Done():
				close(r.out)
				return nil
			default:
				return fmt.Errorf("reading from udp: %w", err)
			}
		}

		// Extracts IP without port
		host, _, _ := net.SplitHostPort(remoteAddr.String())

		// Non-blocking write to channel to avoid stalling the UDP listener
		select {
		case r.out <- RawLog{Data: string(buf[:n]), RemoteIP: host}:
		default:
			// Buffer full, drop to preserve latency
		}
	}
}
