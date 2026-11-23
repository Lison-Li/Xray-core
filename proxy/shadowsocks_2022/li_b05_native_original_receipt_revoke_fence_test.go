package shadowsocks_2022

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// These tests block the REAL native post-Write callback, not a dispatcher
// pipe. A fake physical socket only controls the OS Write return. They do
// not claim real WAL fsync, public Mihomo, or Worker/D1 end-to-end proof.
type liB05BlockingNativeTCPReader struct {
	*liB05NativeReceiptSource
	entered chan struct{}
	release chan struct{}
	acked   atomic.Bool
}

func (r *liB05BlockingNativeTCPReader) LiOnWriteAccepted(n int32) error {
	close(r.entered)
	<-r.release
	if err := r.liB05NativeReceiptSource.LiOnWriteAccepted(n); err != nil {
		return err
	}
	r.acked.Store(true)
	return nil
}

type liB05ImmediateNativeTCPConn struct {
	stdnet.Conn
	writes atomic.Int32
}

func (c *liB05ImmediateNativeTCPConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return len(p), nil
}

type liB05BlockingNativeUDPReader struct {
	*liB05NativePacketSource
	entered chan struct{}
	release chan struct{}
	acked   atomic.Bool
}

func (r *liB05BlockingNativeUDPReader) LiOnWriteAccepted(n int32) error {
	close(r.entered)
	<-r.release
	if err := r.liB05NativePacketSource.LiOnWriteAccepted(n); err != nil {
		return err
	}
	r.acked.Store(true)
	return nil
}

func liB05WaitCallback(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original native post-Write callback never entered")
	}
}

func liB05AssertRemoveBlocked(t *testing.T, deleted <-chan error) {
	t.Helper()
	select {
	case err := <-deleted:
		t.Fatalf("RemoveUser returned BEFORE blocked original WAL receipt: %v", err)
	case <-time.After(65 * time.Millisecond):
		// The already-accepted socket bytes cannot be declared fully
		// settled before the exact UID's Confirm returns.
	}
}

func liB05FinishRemove(t *testing.T, deleted <-chan error) {
	t.Helper()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatalf("RemoveUser failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native account removal failed to complete after receipt")
	}
}

func liB05FenceInbound(t *testing.T, name string) (*MultiUserInbound, *protocol.MemoryUser) {
	t.Helper()
	key := bytes.Repeat([]byte{0x53}, 16)
	i, err := NewMultiServer(b05ModernCoreContext(t), &MultiUserServerConfig{
		Method: MethodAES128GCM,
		Key:    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 16)),
	})
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Email: name, Account: &MemoryAccount{Key: key}}
	if err := i.AddUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return i, user
}

func TestB05ModernNativeTCPRemoveWaitsForActualPostSocketWALReceipt(t *testing.T) {
	i, user := liB05FenceInbound(t, "tcp-wal-fence@qa.invalid")
	a, b := stdnet.Pipe()
	defer a.Close()
	defer b.Close()
	socket := &liB05ImmediateNativeTCPConn{Conn: a}
	accountKey := user.Account.(*MemoryAccount).Key
	binding, ok := i.liB05BindTCPUser(DeriveUserPSKHash(accountKey), socket)
	if !ok || binding.user != user {
		t.Fatal("native original TCP session identity not authenticated")
	}
	method, err := GetCipherMethod(MethodAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	writer := NewServerStreamWriter(socket, method, accountKey, bytes.Repeat([]byte{0x33}, 16))
	writer.liB05NativeTCPBinding = binding
	src := &liB05BlockingNativeTCPReader{
		liB05NativeReceiptSource: &liB05NativeReceiptSource{payload: []byte("confirmed-original-native-downlink"), allow: true},
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- liB05CopyNativeTCPOriginalWithReceipt(src, writer, nil) }()
	liB05WaitCallback(t, src.entered)
	if socket.writes.Load() != 1 {
		t.Fatal("physical original TCP socket Write was not called before blocking WAL callback")
	}
	deleted := make(chan error, 1)
	go func() { deleted <- i.RemoveUser(context.Background(), user.Email) }()
	liB05AssertRemoveBlocked(t, deleted)
	close(src.release)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("original TCP completed socket and WAL ACK failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TCP WAL receipt did not return")
	}
	liB05FinishRemove(t, deleted)
	if !src.acked.Load() || len(src.accepted) != 1 || src.accepted[0] != int32(len(src.payload)) {
		t.Fatalf("original TCP WAL Confirm missing: accepted=%v", src.accepted)
	}
	if socket.writes.Load() != 1 {
		t.Fatal("revocation emitted additional original TCP bytes")
	}
}

func TestB05ModernNativeUDPRemoveWaitsForWholeDatagramBatchWALReceipt(t *testing.T) {
	i, user := liB05FenceInbound(t, "udp-wal-fence@qa.invalid")
	a, b := stdnet.Pipe()
	defer a.Close()
	defer b.Close()
	socket := &liB05NativePacketSocket{Conn: a}
	session := i.udpSessions.GetOrCreate(70329)
	session.Lock()
	session.User = user
	session.UserPSK = user.Account.(*MemoryAccount).Key
	session.Unlock()
	session.currentConn.Store(socket)
	first, second := buf.New(), buf.New()
	first.Write([]byte("first-payload"))
	second.Write([]byte("second-payload"))
	mb := buf.MultiBuffer{first, second}
	plain := mb.Len()
	src := &liB05BlockingNativeUDPReader{
		liB05NativePacketSource: &liB05NativePacketSource{expected: plain},
		entered:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- liB05WriteNativeUDPBatchWithReceipt(
			session, mb, xnet.Destination{},
			func(_ xnet.Destination, p []byte) ([]byte, error) { return append([]byte("encrypted:"), p...), nil },
			src,
		)
	}()
	liB05WaitCallback(t, src.entered)
	if socket.calls != 2 {
		t.Fatalf("expected exactly 2 original encrypted UDP socket writes, got %d", socket.calls)
	}
	deleted := make(chan error, 1)
	go func() { deleted <- i.RemoveUser(context.Background(), user.Email) }()
	liB05AssertRemoveBlocked(t, deleted)
	close(src.release)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("full 2-datagram physical UDP + WAL Confirm: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native UDP WAL receipt never completed")
	}
	liB05FinishRemove(t, deleted)
	if !src.acked.Load() || len(src.accepted) != 1 || src.accepted[0] != plain || len(src.failed) != 0 {
		t.Fatalf("original UDP batch not exactly-once ACKed after physical sockets: accepted=%v failed=%v", src.accepted, src.failed)
	}
	if !session.revoked.Load() {
		t.Fatal("original UDP session remained active after deletion")
	}
	if err := session.WriteToClient([]byte("after-delete")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("revoked native UDP socket accepted a packet: %v", err)
	}
	if socket.calls != 2 {
		t.Fatal("native UDP wrote after revoked account deletion")
	}
}

func TestB05ModernNativeUDPFencedReservedBatchFailsBeforeOriginalWrite(t *testing.T) {
	i, user := liB05FenceInbound(t, "udp-old-intent@qa.invalid")
	session := i.udpSessions.GetOrCreate(70330)
	session.Lock()
	session.User = user
	session.Unlock()
	a, b := stdnet.Pipe()
	defer a.Close()
	defer b.Close()
	socket := &liB05NativePacketSocket{Conn: a}
	session.currentConn.Store(socket)
	if err := i.RemoveUser(context.Background(), user.Email); err != nil {
		t.Fatal(err)
	}
	item := buf.New()
	item.Write([]byte("already-reserved-before-delete"))
	m := buf.MultiBuffer{item}
	src := &liB05NativePacketSource{expected: m.Len()}
	err := liB05WriteNativeUDPBatchWithReceipt(session, m, xnet.Destination{}, func(_ xnet.Destination, p []byte) ([]byte, error) { return p, nil }, src)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("revoked native WAL reservation was not refused: %v", err)
	}
	if socket.calls != 0 || len(src.accepted) != 0 || len(src.failed) != 1 {
		t.Fatalf("revoked native UDP emitted or ACKed plaintext: calls=%d accepted=%v failed=%v", socket.calls, src.accepted, src.failed)
	}
}

func TestB05ModernNativeTCPFencedReservedChunkFailsBeforeOriginalWrite(t *testing.T) {
	i, user := liB05FenceInbound(t, "tcp-old-intent@qa.invalid")
	a, b := stdnet.Pipe()
	defer a.Close()
	defer b.Close()
	socket := &liB05ImmediateNativeTCPConn{Conn: a}
	binding, ok := i.liB05BindTCPUser(DeriveUserPSKHash(user.Account.(*MemoryAccount).Key), socket)
	if !ok {
		t.Fatal("native TCP was not authenticated")
	}
	if err := i.RemoveUser(context.Background(), user.Email); err != nil {
		t.Fatal(err)
	}
	method, err := GetCipherMethod(MethodAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	writer := NewServerStreamWriter(socket, method, user.Account.(*MemoryAccount).Key, bytes.Repeat([]byte{0x44}, 16))
	writer.liB05NativeTCPBinding = binding
	src := &liB05NativeReceiptSource{payload: []byte("late-reserved-original-tcp"), allow: true}
	err = liB05CopyNativeTCPOriginalWithReceipt(src, writer, nil)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("revoked TCP late reserved chunk did not fail closed: %v", err)
	}
	if socket.writes.Load() != 0 || len(src.accepted) != 0 || len(src.failed) != 1 {
		t.Fatalf("removed TCP user emitted plaintext or got ACK: writes=%d accepted=%v failed=%v", socket.writes.Load(), src.accepted, src.failed)
	}
}

var _ = io.ErrShortWrite
