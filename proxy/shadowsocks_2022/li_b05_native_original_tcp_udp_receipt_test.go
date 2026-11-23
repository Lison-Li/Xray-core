package shadowsocks_2022

import (
	"bytes"
	"errors"
	"io"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// These tests exercise the real native ServerStreamWriter and
// ServerUDPSession.WriteToClient return boundaries, with only a controllable
// fake OS socket write return. They are NOT external Mihomo, fsynced WAL,
// or deployed Worker/D1 acceptance.
type liB05NativeReceiptSource struct {
	payload  []byte
	read     bool
	accepted []int32
	failed   []error
	allow    bool
}

func (s *liB05NativeReceiptSource) Read(out []byte) (int, error) {
	if s.read {
		return 0, io.EOF
	}
	s.read = true
	return copy(out, s.payload), nil
}
func (s *liB05NativeReceiptSource) LiB05StrictClientConnReceipt() bool { return s.allow }
func (s *liB05NativeReceiptSource) LiOnWriteAccepted(n int32) error {
	s.accepted = append(s.accepted, n)
	return nil
}

func (s *liB05NativeReceiptSource) LiOnWriteFailed(err error) {
	s.failed = append(s.failed, err)
}

type liB05OriginalTCPPhysical struct {
	short  bool
	fail   error
	calls  int
	actual []int
}

func (w *liB05OriginalTCPPhysical) Write(p []byte) (int, error) {
	w.calls++
	if w.fail != nil {
		return 0, w.fail
	}
	n := len(p)
	if w.short {
		n--
	}
	w.actual = append(w.actual, n)
	return n, nil
}

func TestB05ModernSS2022NativeTCPFinalOriginalSocketReceiptBoundary(t *testing.T) {
	method, err := GetCipherMethod(MethodAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	psk := bytes.Repeat([]byte{0x71}, 16)
	salt := bytes.Repeat([]byte{0x61}, 16)
	for _, tc := range []struct {
		name         string
		short        bool
		fail         error
		wantAccepted bool
	}{
		{"full_physical_encrypted_socket", false, nil, true},
		{"short_physical_encrypted_socket", true, nil, false},
		{"socket_error", false, io.ErrClosedPipe, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &liB05NativeReceiptSource{payload: []byte("native-SS2022-downlink-original"), allow: true}
			socket := &liB05OriginalTCPPhysical{short: tc.short, fail: tc.fail}
			writer := NewServerStreamWriter(socket, method, psk, salt)
			err := liB05CopyNativeTCPOriginalWithReceipt(source, writer, nil)
			if tc.wantAccepted {
				if err != nil || len(source.accepted) != 1 || source.accepted[0] != int32(len(source.payload)) || len(source.failed) != 0 || socket.calls != 1 {
					t.Fatalf("original TCP successful socket receipt=%v accepted=%v failed=%v wirecalls=%d", err, source.accepted, source.failed, socket.calls)
				}
			} else {
				if err == nil || len(source.accepted) != 0 || len(source.failed) != 1 || socket.calls != 1 {
					t.Fatalf("original TCP failed socket incorrectly ACKed: err=%v accepted=%v failed=%v calls=%d", err, source.accepted, source.failed, socket.calls)
				}
				if tc.short && !errors.Is(err, io.ErrShortWrite) {
					t.Fatalf("partial original TCP encrypted socket: %v", err)
				}
			}
		})
	}
	rejected := &liB05NativeReceiptSource{allow: false, payload: []byte("refuse")}
	wire := &liB05OriginalTCPPhysical{}
	if err := liB05CopyNativeTCPOriginalWithReceipt(rejected, NewServerStreamWriter(wire, method, psk, salt), nil); err == nil || wire.calls != 0 {
		t.Fatalf("reader without explicit strict receipt capability admitted: %v calls=%d", err, wire.calls)
	}
}

// Implements a buf.Reader with a real MultiBuffer and reserves its logical
// plaintext bytes before returning. No actual li_meter ledger in this test.
type liB05NativePacketSource struct {
	expected int32
	accepted []int32
	failed   []error
}

func (s *liB05NativePacketSource) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }
func (s *liB05NativePacketSource) LiOnWriteAccepted(n int32) error {
	if n != s.expected {
		return errors.New("wrong plaintext receipt count")
	}
	s.accepted = append(s.accepted, n)
	return nil
}
func (s *liB05NativePacketSource) LiOnWriteFailed(e error) { s.failed = append(s.failed, e) }

type liB05NativePacketSocket struct {
	stdnet.Conn
	shortAt int
	calls   int
	emitted [][]byte
}

func (w *liB05NativePacketSocket) Write(p []byte) (int, error) {
	w.calls++
	w.emitted = append(w.emitted, append([]byte(nil), p...))
	if w.shortAt > 0 && w.calls == w.shortAt {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestB05ModernSS2022NativeUDPMultiDatagramOriginalSocketReceiptBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		shortAt  int
		accepted bool
	}{
		{"both_physical_datagrams_complete", 0, true},
		{"second_physical_datagram_short", 2, false},
		{"first_physical_datagram_short", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			physical, peer := stdnet.Pipe()
			defer physical.Close()
			defer peer.Close()
			socket := &liB05NativePacketSocket{Conn: physical, shortAt: tc.shortAt}
			session := &ServerUDPSession{}
			session.currentConn.Store(socket)
			a, b := buf.New(), buf.New()
			a.Write([]byte("alpha"))
			b.Write([]byte("bravo-123"))
			batch := buf.MultiBuffer{a, b}
			size := batch.Len()
			reader := &liB05NativePacketSource{expected: size}
			// The test encryption function adds a deterministic prefix only;
			// the real handleUDPResponse uses native encodeServerUDPPacket.
			encoder := func(_ xnet.Destination, payload []byte) ([]byte, error) {
				return append([]byte("encrypted-frame:"), payload...), nil
			}
			err := liB05WriteNativeUDPBatchWithReceipt(session, batch, xnet.Destination{}, encoder, reader)
			if tc.accepted {
				if err != nil || len(reader.accepted) != 1 || reader.accepted[0] != size || len(reader.failed) != 0 || socket.calls != 2 {
					t.Fatalf("original UDP batch receipt err=%v ACK=%v failed=%v calls=%d", err, reader.accepted, reader.failed, socket.calls)
				}
			} else {
				if !errors.Is(err, io.ErrShortWrite) || len(reader.accepted) != 0 || len(reader.failed) != 1 || socket.calls != tc.shortAt {
					t.Fatalf("partial original UDP socket incorrectly confirmed: err=%v ACK=%v failed=%v calls=%d", err, reader.accepted, reader.failed, socket.calls)
				}
			}
		})
	}
}
