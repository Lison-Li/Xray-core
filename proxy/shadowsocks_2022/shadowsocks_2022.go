package shadowsocks_2022

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func (s *ServerUDPSession) UpdateConn(conn stat.Connection) {
	s.currentConn.Store(conn)
	s.timer.Update()
}

func (s *ServerUDPSession) WriteToClient(b []byte) error {
	// A completed RemoveUser must imply no old account datagram is still
	// inside the physical encrypted socket Write. The exclusive revoke lock
	// waits for this shared lock, then future calls observe revoked=true.
	s.writeGate.RLock()
	defer s.writeGate.RUnlock()
	// The caller may still be in the response goroutine after the account was
	// removed. A closed/invalidated session must not emit any encrypted reply.
	if s.revoked.Load() {
		return ErrInvalidRequest
	}
	connVal := s.currentConn.Load()
	if connVal == nil {
		return errors.New("client connection closed")
	}
	conn, ok := connVal.(stat.Connection)
	if !ok || conn == nil {
		return errors.New("client connection closed")
	}
	// This is the ORIGINAL encrypted UDP socket, not a dispatcher pipe.
	// net.Conn.Write may legally report n < len(b) with err == nil.
	// Treat that as a failed datagram, never a successful final Writer
	// acknowledgment or an opportunity to charge the full payload.
	n, err := conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *ServerUDPSession) Close() {
	if s.timer != nil {
		s.timer.SetTimeout(0)
	}
	if link := s.link.Load(); link != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
}

func (s *ServerUDPSession) EnsureLink(
	ctx context.Context,
	conn stat.Connection,
	dest net.Destination,
	dispatcher routing.Dispatcher,
	policyManager policy.Manager,
	responseEncoder func(dest net.Destination, payload []byte) ([]byte, error),
) (*transport.Link, error) {
	s.Lock()
	defer s.Unlock()

	// Removal may have invalidated this session between authenticated UDP
	// packet decoding and new link creation. Never dispatch a revoked user.
	if s.revoked.Load() {
		return nil, ErrInvalidRequest
	}
	if link := s.link.Load(); link != nil {
		s.UpdateConn(conn)
		return link, nil
	}

	s.currentConn.Store(conn)

	sessCtx, cancel := context.WithCancel(ctx)
	inbound := session.InboundFromContext(sessCtx)
	if inbound != nil && s.User != nil {
		inbound.User = s.User
	}
	var email string
	var level uint32
	if s.User != nil {
		email = s.User.Email
		level = s.User.Level
	}
	sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  email,
	})

	link, err := dispatcher.Dispatch(sessCtx, dest)
	if err != nil {
		cancel()
		return nil, err
	}

	sessionPolicy := policyManager.ForLevel(level)
	s.timer = signal.CancelAfterInactivity(sessCtx, func() {
		if s.manager != nil {
			s.manager.Delete(s.SessionID)
		}
		s.Close()
		cancel()
	}, sessionPolicy.Timeouts.ConnectionIdle)
	s.link.Store(link)

	go handleUDPResponse(s, link, dest, responseEncoder)
	return link, nil
}

// ResetTCPConn sets SO_LINGER to 0 per SIP022 §3.1.4 to consistently send RST on close
// when handshake or header validation fails.
func ResetTCPConn(conn net.Conn) {
	rawConn, _, _ := proxy.UnwrapRawConn(conn)
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
}

func handleUDPResponse(s *ServerUDPSession, link *transport.Link, fallbackDest net.Destination, encode func(dest net.Destination, payload []byte) ([]byte, error)) {
	defer s.timer.SetTimeout(0)
	for {
		resMb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			// A strict WAL reader may have fsynced an intent before its
			// underlying transport returned a simultaneous read error.
			if receipt, ok := link.Reader.(liB05NativePacketReceiptReader); ok {
				receipt.LiOnWriteFailed(err)
			}
			buf.ReleaseMulti(resMb)
			return
		}
		s.timer.Update()
		if err := liB05WriteNativeUDPBatchWithReceipt(s, resMb, fallbackDest, encode, link.Reader); err != nil {
			return
		}
	}
}

const (
	HeaderTypeClient              = 0
	HeaderTypeServer              = 1
	MaxPaddingLength              = 900
	PacketNonceSize               = 24
	MaxPacketSize                 = 65535
	RequestHeaderFixedChunkLength = 1 + 8 + 2 // Type (1B) + Timestamp (8B) + VarHeaderLen (2B)
	PacketMinimalHeaderSize       = 30
	StreamNonceSize               = 12
	AESBlockSize                  = 16
	AEADTagSize                   = 16
)

var zeroPadding [MaxPaddingLength]byte

const (
	MethodAES128GCM        = "2022-blake3-aes-128-gcm"
	MethodAES256GCM        = "2022-blake3-aes-256-gcm"
	MethodChaCha20Poly1305 = "2022-blake3-chacha20-poly1305"
)

var (
	ErrBadKey            = errors.New("bad key")
	ErrBadHeaderType     = errors.New("bad header type")
	ErrBadTimestamp      = errors.New("bad timestamp")
	ErrSaltNotUnique     = errors.New("salt not unique")
	ErrPacketIdNotUnique = errors.New("packet id not unique")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrPacketTooLarge    = errors.New("packet too large")
	ErrNoPadding         = errors.New("bad request: missing payload or padding")
	ErrInvalidRequest    = errors.New("invalid request")
)
