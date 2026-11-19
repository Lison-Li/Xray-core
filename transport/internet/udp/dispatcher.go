package udp

import (
	"context"
	goerrors "errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type ResponseCallback func(ctx context.Context, packet *udp.Packet)

// FinalWriterResponseCallback returns the *actual final socket Writer*
// outcome. It is intentionally separate from the historical void callback:
// calling LiOnWriteAccepted before this returns nil would turn an unconfirmed
// Trojan UDP downlink reservation into fictitious revenue.
type FinalWriterResponseCallback func(ctx context.Context, packet *udp.Packet) error

type connEntry struct {
	link   *transport.Link
	timer  *signal.ActivityTimer
	cancel context.CancelFunc
	closed bool
}

func (c *connEntry) Close() error {
	c.timer.SetTimeout(0)
	return nil
}

func (c *connEntry) terminate() {
	if c.closed {
		panic("terminate called more than once")
	}
	c.closed = true
	c.cancel()
	common.Interrupt(c.link.Reader)
	common.Interrupt(c.link.Writer)
}

type Dispatcher struct {
	sync.RWMutex
	conn       *connEntry
	dispatcher routing.Dispatcher
	callback   ResponseCallback
	finalWriterCallback FinalWriterResponseCallback
	callClose  func() error
	closed     bool
}

func NewDispatcher(dispatcher routing.Dispatcher, callback ResponseCallback) *Dispatcher {
	return &Dispatcher{
		dispatcher: dispatcher,
		callback:   callback,
	}
}

// NewDispatcherWithFinalWriterReceipt is used only by native Trojan UDP,
// where the response is written through a *direct* PacketWriter callback,
// not buf.Copy. The legacy callback cannot prove post-socket acceptance.
// The verified Writer receives its receipt after every buffer in a staged
// ReadMultiBuffer has been handed to the real PacketWriter successfully.
func NewDispatcherWithFinalWriterReceipt(dispatcher routing.Dispatcher, callback FinalWriterResponseCallback) *Dispatcher {
	return &Dispatcher{
		dispatcher:        dispatcher,
		finalWriterCallback: callback,
	}
}

func (v *Dispatcher) RemoveRay() {
	v.Lock()
	defer v.Unlock()
	v.closed = true
	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
	}
}

func (v *Dispatcher) getInboundRay(ctx context.Context, dest net.Destination) (*connEntry, error) {
	v.Lock()
	defer v.Unlock()

	if v.closed {
		return nil, errors.New("dispatcher is closed")
	}

	if v.conn != nil {
		if v.conn.closed {
			v.conn = nil
		} else {
			return v.conn, nil
		}
	}

	errors.LogInfo(ctx, "establishing new connection for ", dest)

	ctx, cancel := context.WithCancel(ctx)

	link, err := v.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		cancel()
		return nil, errors.New("failed to dispatch request to ", dest).Base(err)
	}

	entry := &connEntry{
		link:   link,
		cancel: cancel,
	}

	entry.timer = signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)
	v.conn = entry
	go handleInput(ctx, entry, dest, v.callback, v.finalWriterCallback, v.callClose)
	return entry, nil
}

func (v *Dispatcher) Dispatch(ctx context.Context, destination net.Destination, payload *buf.Buffer) {
	// TODO: Add user to destString
	errors.LogDebug(ctx, "dispatch request to: ", destination)

	conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		return
	}
	outputStream := conn.link.Writer
	if outputStream != nil {
		if err := outputStream.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to write first UDP payload")
			conn.Close()
			return
		}
	}
}

func handleInput(ctx context.Context, conn *connEntry, dest net.Destination, callback ResponseCallback, finalWriterCallback FinalWriterResponseCallback, callClose func() error) {
	defer func() {
		conn.Close()
		if callClose != nil {
			callClose()
		}
	}()

	input := conn.link.Reader
	timer := conn.timer

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mb, err := input.ReadMultiBuffer()
		if err != nil {
			if !goerrors.Is(err, io.EOF) {
				errors.LogInfoInner(ctx, err, "failed to handle UDP input")
			}
			return
		}
		timer.Update()
		// The original void-callback API stays byte-for-byte unchanged for
		// every non-Trojan UDP use. It cannot authorize B05 WAL Confirm.
		if finalWriterCallback == nil {
			for _, b := range mb {
				if b.UDP != nil {
					dest = *b.UDP
				}
				callback(ctx, &udp.Packet{Payload: b, Source: dest})
			}
			continue
		}

		// Stage size is measured BEFORE PacketWriter consumes/releases its
		// buffers. The final callback returns only when the underlying
		// Trojan framed TLS socket Writer returns success or failure.
		acceptedBytes := mb.Len()
		for i, b := range mb {
			if b.UDP != nil {
				dest = *b.UDP
			}
			if writeErr := finalWriterCallback(ctx, &udp.Packet{Payload: b, Source: dest}); writeErr != nil {
				// One or more datagrams may have reached the socket. Never
				// invent an ACK or refund. The source ledger's own fail-
				// closed handling quarantines the original reservation.
				if receipt, ok := input.(interface{ LiOnWriteFailed(error) }); ok {
					receipt.LiOnWriteFailed(writeErr)
				}
				for _, remaining := range mb[i+1:] {
					remaining.Release()
				}
				errors.LogWarningInner(ctx, writeErr, "Trojan final UDP socket Writer did not accept complete batch")
				return
			}
		}
		if acceptedBytes > 0 {
			if receipt, ok := input.(interface{ LiOnWriteAccepted(int32) error }); ok {
				if writeErr := receipt.LiOnWriteAccepted(acceptedBytes); writeErr != nil {
				// A physically accepted socket write with no fsynced Confirm
				// is indeterminate and must remain fail-closed.
				errors.LogWarningInner(ctx, writeErr, "Trojan UDP socket Writer receipt not durable")
				return
				}
			}
		}
	}
}

type dispatcherConn struct {
	dispatcher *Dispatcher
	cache      chan *udp.Packet
	done       *done.Instance
	ctx        context.Context
}

func DialDispatcher(ctx context.Context, dispatcher routing.Dispatcher) (net.PacketConn, error) {
	c := &dispatcherConn{
		cache: make(chan *udp.Packet, 16),
		done:  done.New(),
		ctx:   ctx,
	}

	d := &Dispatcher{
		dispatcher: dispatcher,
		callback:   c.callback,
		callClose:  c.Close,
	}
	c.dispatcher = d
	return c, nil
}

func (c *dispatcherConn) callback(ctx context.Context, packet *udp.Packet) {
	select {
	case <-c.done.Wait():
		packet.Payload.Release()
		return
	case c.cache <- packet:
	default:
		packet.Payload.Release()
		return
	}
}

func (c *dispatcherConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var packet *udp.Packet
s:
	select {
	case <-c.done.Wait():
		select {
		case packet = <-c.cache:
			break s
		default:
			return 0, nil, io.EOF
		}
	case packet = <-c.cache:
	}
	return copy(p, packet.Payload.Bytes()), &net.UDPAddr{
		IP:   packet.Source.Address.IP(),
		Port: int(packet.Source.Port),
	}, nil
}

func (c *dispatcherConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buffer := buf.New()
	raw := buffer.Extend(buf.Size)
	n := copy(raw, p)
	buffer.Resize(0, int32(n))

	destination := net.DestinationFromAddr(addr)
	buffer.UDP = &destination
	c.dispatcher.Dispatch(c.ctx, destination, buffer)
	return n, nil
}

func (c *dispatcherConn) Close() error {
	return c.done.Close()
}

func (c *dispatcherConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   []byte{0, 0, 0, 0},
		Port: 0,
	}
}

func (c *dispatcherConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetWriteDeadline(t time.Time) error {
	return nil
}
