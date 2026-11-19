package shadowsocks_2022

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// A test-only socket can return n < len(payload) with err == nil.  The
// original native SS2022 WritePacket ignored n, incorrectly treating this
// physical partial encrypted UDP write as successful.  No WAL ACK is faked.
type b05SS2022NativeShortSocket struct {
	net.Conn
	n   int
	err error
}

func (c *b05SS2022NativeShortSocket) Write(p []byte) (int, error) {
	return c.n, c.err
}

func TestB05SS2022NativeEncryptedUDPSocketWriteMustBeComplete(t *testing.T) {
	payload := []byte("encrypted-ss2022-native-udp-datagram")
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{name: "short-nil-error", n: len(payload) - 1, want: io.ErrShortWrite},
		{name: "zero-nil-error", n: 0, want: io.ErrShortWrite},
		{name: "original-socket-error", n: 1, err: io.ErrClosedPipe, want: io.ErrClosedPipe},
		{name: "complete-original-write", n: len(payload)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &natPacketConn{&b05SS2022NativeShortSocket{n: tc.n, err: tc.err}}
			err := conn.WritePacket(B.As(payload), M.Socksaddr{})
			if tc.want == nil && err != nil {
				t.Fatalf("full original write unexpectedly failed: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("socket result %d/%d, %v: got %v, want %v",
					tc.n, len(payload), tc.err, err, tc.want)
			}
		})
	}

	// This is a genuine in-process net.Conn pair rather than only a
	// fabricated Write return value.  A physical peer must receive all bytes
	// before a successful native lower socket write can return.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(client, buf); err != nil {
			received <- nil
			return
		}
		received <- buf
	}()
	conn := &natPacketConn{server}
	if err := conn.WritePacket(B.As(payload), M.Socksaddr{}); err != nil {
		t.Fatalf("real in-process full WritePacket failed: %v", err)
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Fatal("original socket did not deliver the complete datagram")
	}
	t.Log("B05_SS2022_NATIVE_ENCRYPTED_SOCKET_FULL_SHORT_ERROR_WRITE_BOUNDARY=PASS")
}
