package shadowsocks_2022

import (
    "errors"
    "io"
    stdnet "net"
    "testing"
)

// Real ServerUDPSession.WriteToClient edge, with a stub at its *net.Conn*
// boundary only. This is a unit fault-injection test, NOT a real off-host
// encrypted UDP packet acceptance or fsynced accounting checkpoint.
type b05ShortPacketConn struct {
    stdnet.Conn
    n int
    writeErr error
    calls int
    seen []byte
}
func (c *b05ShortPacketConn) Write(p []byte) (int,error) {
    c.calls++
    c.seen=append([]byte(nil),p...)
    return c.n,c.writeErr
}

func TestB05ModernSS2022ActualOriginalUDPSocketWriteMustRejectShortWrite(t *testing.T) {
    injected:=errors.New("injected original packet socket write failure")
    packet:=[]byte("encrypted-external-ss2022-native-udp")
    cases:=[]struct{
        label string
        n int
        underlying error
        want error
    }{
        {"full-original-datagram",len(packet),nil,nil},
        {"short-original-datagram-no-OS-error",len(packet)-1,nil,io.ErrShortWrite},
        {"zero-byte-original-datagram-no-OS-error",0,nil,io.ErrShortWrite},
        {"negative-invalid-OS-count",-1,nil,io.ErrShortWrite},
        {"overlong-invalid-OS-count",len(packet)+1,nil,io.ErrShortWrite},
        {"actual-socket-error",0,injected,injected},
        {"partial-with-actual-socket-error",len(packet)-2,injected,injected},
    }
    for _,tc:=range cases {
        t.Run(tc.label,func(t *testing.T){
            local,peer:=stdnet.Pipe()
            defer local.Close()
            defer peer.Close()
            ioConn:=&b05ShortPacketConn{Conn:local,n:tc.n,writeErr:tc.underlying}
            session:=&ServerUDPSession{}
            session.currentConn.Store(ioConn)
            err:=session.WriteToClient(packet)
            if !errors.Is(err,tc.want) || ((tc.want==nil)!=(err==nil)){
                t.Fatalf("original UDP socket write acceptance=%v, expected=%v",err,tc.want)
            }
            if ioConn.calls!=1 || string(ioConn.seen)!=string(packet) {
                t.Fatalf("original native UDP socket called wrong number of times or with wrong encrypted bytes: calls=%d",ioConn.calls)
            }
        })
    }
}

func TestB05ModernSS2022NativeUDPSocketNoExistingClientRefuses(t *testing.T) {
    session:=&ServerUDPSession{}
    if err:=session.WriteToClient([]byte("encrypted"));err==nil{
        t.Fatal("no live client original UDP Writer must fail before any phantom successful receipt")
    }
}
