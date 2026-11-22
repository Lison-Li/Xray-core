package shadowsocks_2022

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

// This is a true original net.Conn cancellation unit test, not an external
// proxy/Mihomo or production Worker billing acceptance.
func TestB05ModernSS2022TCPOriginalConnectionRemoveAndSurvivor(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		keyLen       int
	}{
		{"AES128", MethodAES128GCM, 16},
		{"AES256", MethodAES256GCM, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound, err := NewMultiServer(b05ModernCoreContext(t), &MultiUserServerConfig{
				Method: tc.method,
				Key:    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x15}, tc.keyLen)),
			})
			if err != nil {
				t.Fatal(err)
			}
			oldKey := bytes.Repeat([]byte{0x41}, tc.keyLen)
			newKey := bytes.Repeat([]byte{0x43}, tc.keyLen)
			bKey := bytes.Repeat([]byte{0x42}, tc.keyLen)
			a := &protocol.MemoryUser{Email: "tcp-a@qa.invalid", Account: &MemoryAccount{Key: oldKey}}
			b := &protocol.MemoryUser{Email: "tcp-b@qa.invalid", Account: &MemoryAccount{Key: bKey}}
			for _, u := range []*protocol.MemoryUser{a, b} {
				if err := inbound.AddUser(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			}
			oldConn, oldPeer := stdnet.Pipe()
			defer oldConn.Close()
			defer oldPeer.Close()
			bConn, bPeer := stdnet.Pipe()
			defer bConn.Close()
			defer bPeer.Close()
			aBinding, ok := inbound.liB05BindTCPUser(DeriveUserPSKHash(oldKey), oldConn)
			if !ok || aBinding.user != a {
				t.Fatal("original A TCP identity was not bound")
			}
			bBinding, ok := inbound.liB05BindTCPUser(DeriveUserPSKHash(bKey), bConn)
			if !ok || bBinding.user != b {
				t.Fatal("B TCP identity was not bound")
			}
			if err := inbound.RemoveUser(context.Background(), a.Email); err != nil {
				t.Fatal(err)
			}
			_ = oldPeer.SetReadDeadline(time.Now().Add(time.Second))
			one := make([]byte, 1)
			if _, err := oldPeer.Read(one); !errors.Is(err, io.EOF) {
				t.Fatalf("A original socket still open after RemoveUser returned: %v", err)
			}
			if _, err := oldConn.Write([]byte("after-removal")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("old A original socket accepted bytes: %v", err)
			}
			inbound.liB05UnbindTCPUser(aBinding)
			if len(inbound.tcpConnections[a]) != 0 {
				t.Fatal("old A TCP binding leaked")
			}
			_ = bPeer.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			if _, err := bPeer.Read(one); err == nil {
				t.Fatal("unexpected B data")
			} else if e, ok := err.(stdnet.Error); !ok || !e.Timeout() {
				t.Fatalf("unrelated B TCP was wrongly closed: %v", err)
			}
			inbound.liB05UnbindTCPUser(bBinding)
			if _, ok := inbound.liB05BindTCPUser(DeriveUserPSKHash(oldKey), oldConn); ok {
				t.Fatal("removed original A key admitted after deletion")
			}
			fresh := &protocol.MemoryUser{Email: a.Email, Account: &MemoryAccount{Key: newKey}}
			if err := inbound.AddUser(context.Background(), fresh); err != nil {
				t.Fatal(err)
			}
			if _, ok := inbound.liB05BindTCPUser(DeriveUserPSKHash(oldKey), oldConn); ok {
				t.Fatal("rotated old key accepted by new account")
			}
			freshConn, freshPeer := stdnet.Pipe()
			defer freshConn.Close()
			defer freshPeer.Close()
			freshBinding, ok := inbound.liB05BindTCPUser(DeriveUserPSKHash(newKey), freshConn)
			if !ok || freshBinding.user != fresh {
				t.Fatal("rotated fresh user could not open a TCP socket")
			}
			inbound.liB05UnbindTCPUser(freshBinding)
			t.Log("B05_MODERN_SS2022_TCP_OLD_A_CLOSED_SURVIVOR_B_OPEN_ROTATED_NEW_A=PASS_UNIT")
		})
	}
}

// Concurrent authentication and deletion are linearized by the same mutex.
// Either a successful binding is synchronously closed, or it is refused.
func TestB05ModernSS2022TCPRemoveRacesAuthentication(t *testing.T) {
	inbound, err := NewMultiServer(b05ModernCoreContext(t), &MultiUserServerConfig{
		Method: MethodAES128GCM,
		Key:    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 16)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 48; j++ {
		key := bytes.Repeat([]byte{byte(60 + j)}, 16)
		u := &protocol.MemoryUser{Email: fmt.Sprintf("tcp-race-%d@qa.invalid", j), Account: &MemoryAccount{Key: key}}
		if err := inbound.AddUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
		conn, peer := stdnet.Pipe()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var binding *liB05TCPBinding
		var accepted bool
		var removeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			binding, accepted = inbound.liB05BindTCPUser(DeriveUserPSKHash(key), conn)
		}()
		go func() { defer wg.Done(); <-start; removeErr = inbound.RemoveUser(context.Background(), u.Email) }()
		close(start)
		wg.Wait()
		if removeErr != nil {
			t.Fatalf("remove race %d: %v", j, removeErr)
		}
		if accepted {
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("accepted old socket not closed after removal in race %d: %v", j, err)
			}
			inbound.liB05UnbindTCPUser(binding)
		} else if _, ok := inbound.liB05BindTCPUser(DeriveUserPSKHash(key), conn); ok {
			t.Fatalf("removed account re-authorized at race %d", j)
		}
		_ = conn.Close()
		_ = peer.Close()
	}
}
