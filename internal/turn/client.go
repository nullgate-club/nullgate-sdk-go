package turn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/logging"
	pionturn "github.com/pion/turn/v4"
)

// turnAllocation owns only a proxy/direct TCP stream and Pion's relay allocation.
// Pion owns STUN framing, authentication, refreshes and the deallocation request.
type turnAllocation struct {
	stream     net.Conn
	client     *pionturn.Client
	readerDone chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex
	relay      net.PacketConn
	closed     bool
}

func (a *turnAllocation) attach(relay net.PacketConn) bool {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		// Cancellation can race with a successful Allocate. Never orphan the
		// just-returned allocation even if the control stream is already closed.
		relay.Close()
		return false
	}
	a.relay = relay
	a.mu.Unlock()
	return true
}

func (a *turnAllocation) close() {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		relay := a.relay
		a.mu.Unlock()
		// UDPConn.Close sends Refresh(lifetime=0) without waiting for its reply.
		// Bound the write before closing transactions and the owned TCP stream.
		_ = a.stream.SetWriteDeadline(time.Now().Add(time.Second))
		if relay != nil {
			_ = relay.Close()
		}
		a.client.Close()
		_ = a.stream.Close()
		<-a.readerDone
	})
}

// Observe retains the provider allocation until cancellation or failure.
func Observe(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), server Server, report func(*Observation) error) error {
	started := time.Now()
	address := net.JoinHostPort(server.Host, strconv.Itoa(server.Port))
	stream, err := dial(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() == nil {
			return report(nil)
		}
		return nil
	}
	if ctx.Err() != nil {
		stream.Close()
		return nil
	}
	packets := pionturn.NewSTUNConn(stream)
	client, err := pionturn.NewClient(&pionturn.ClientConfig{
		Conn: packets,
		// STUNConn ignores WriteTo's address: this is the actual stream peer,
		// avoiding a second, potentially off-proxy DNS lookup of the TURN host.
		TURNServerAddr: stream.RemoteAddr().String(),
		Username:       server.Username, Password: server.Credential,
		LoggerFactory: &logging.DefaultLoggerFactory{
			Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled,
		},
	})
	if err != nil {
		stream.Close()
		if ctx.Err() == nil {
			return report(nil)
		}
		return nil
	}
	allocation := &turnAllocation{stream: stream, client: client, readerDone: make(chan struct{})}
	// HandleInbound is the public Pion alternative to Listen. Owning this read
	// pump lets Close join it rather than leave an untracked provider goroutine.
	go func() {
		defer close(allocation.readerDone)
		defer client.Close()
		buffer := make([]byte, 65535)
		for {
			n, from, err := packets.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := client.HandleInbound(buffer[:n], from); err != nil {
				return
			}
		}
	}()
	stopContext := context.AfterFunc(ctx, allocation.close)
	defer func() {
		stopContext()
		allocation.close()
	}()
	// TURN/TCP describes the route to the server. The relay itself is a normal
	// UDP allocation; no local UDP socket or host candidate is ever opened.
	relay, err := client.Allocate()
	if err != nil {
		if ctx.Err() == nil {
			return report(nil)
		}
		return nil
	}
	if !allocation.attach(relay) || ctx.Err() != nil {
		return nil
	}
	relayAddress, ok := relay.LocalAddr().(*net.UDPAddr)
	if !ok || relayAddress.IP == nil || relayAddress.IP.IsUnspecified() || relayAddress.Port < 1 || relayAddress.Port > 65535 {
		return report(nil)
	}
	elapsed := float64(time.Since(started)) / float64(time.Millisecond)
	candidate := Candidate{
		Value:     fmt.Sprintf("candidate:1 1 udp 16777215 %s %d typ relay", relayAddress.IP.String(), relayAddress.Port),
		ElapsedMS: elapsed,
	}
	observation := &Observation{
		Candidates:   []Candidate{candidate},
		CompleteAtMS: float64(time.Since(started)) / float64(time.Millisecond),
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := report(observation); err != nil {
		return err
	}
	// Keep the provider's refresh timers and allocation alive after reporting.
	// ice.release or profile cancellation owns the actual deallocation.
	select {
	case <-ctx.Done():
		return nil
	case <-allocation.readerDone:
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("TURN/TCP connection closed unexpectedly")
	}
}
