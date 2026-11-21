package shadowsocks_2022

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "errors"
    "io"
    "testing"

    "github.com/xtls/xray-core/common/net"
)

// Physical encrypted writer deliberately violates the io.Writer contract.
// A strict accounting layer must still refuse its nil-error short return.
type liB05PartialTCPWriter struct {
    n int
    err error
    calls int
    wrote int
}
func (w *liB05PartialTCPWriter) Write(p []byte) (int,error) {
    w.calls++
    if w.err != nil { return w.n,w.err }
    w.wrote=len(p)
    return w.n,nil
}
func liB05TCPAEAD(t *testing.T) cipher.AEAD {
    t.Helper()
    block,err:=aes.NewCipher(bytes.Repeat([]byte{0x71},16))
    if err!=nil { t.Fatal(err) }
    a,err:=cipher.NewGCM(block)
    if err!=nil { t.Fatal(err) }
    return a
}
func TestB05ModernSS2022OriginalTCPPhysicalEncryptedShortWriteRefused(t *testing.T) {
    cases:=[]struct {name string; n int; err error; wantErr error}{
        {"zero_nil",0,nil,io.ErrShortWrite},
        {"one_nil",1,nil,io.ErrShortWrite},
        {"negative_nil",-1,nil,io.ErrShortWrite},
        {"oversize_nil",100000,nil,io.ErrShortWrite},
        {"syscall_error",1,io.ErrClosedPipe,io.ErrClosedPipe},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            w:=&liB05PartialTCPWriter{n:tc.n,err:tc.err}
            sw:=NewStreamWriter(w,liB05TCPAEAD(t))
            err:=sw.WriteChunk([]byte("original-encrypted-TCP-body"))
            if !errors.Is(err,tc.wantErr) {
                t.Fatalf("physical original encrypted TCP write acceptance=%v want=%v",err,tc.wantErr)
            }
            if w.calls!=1 {t.Fatalf("actual socket invoked %d times",w.calls)}
        })
    }
    successPayload:=[]byte("complete-original-TCP-frame")
    okWriter:=&liB05PartialTCPWriter{}
    // Exact encrypted frame length = 2 byte length + two AEAD tags + body.
    okWriter.n=2+2*AEADTagSize+len(successPayload)
    if err:=NewStreamWriter(okWriter,liB05TCPAEAD(t)).WriteChunk(successPayload);err!=nil {
        t.Fatalf("valid complete encrypted frame rejected: %v",err)
    }
    if okWriter.wrote!=okWriter.n {t.Fatalf("test writer length mismatch: %d != %d",okWriter.wrote,okWriter.n)}
}
func TestB05ModernSS2022TCPHandshakeShortWriteRefused(t *testing.T) {
    method,err:=GetCipherMethod(MethodAES128GCM)
    if err!=nil{t.Fatal(err)}
    psk:=bytes.Repeat([]byte{0x21},16)
    salt:=bytes.Repeat([]byte{0x42},16)
    dest:=net.TCPDestination(net.DomainAddress("example.invalid"),net.Port(443))
    // Incoming client's original physical encrypted handshake.
    for _,tc:=range []struct{name string;n int;err error;want error}{
        {"client_zero",0,nil,io.ErrShortWrite},
        {"client_one",1,nil,io.ErrShortWrite},
        {"client_syscall",1,io.ErrClosedPipe,io.ErrClosedPipe},
    } {
        t.Run(tc.name,func(t *testing.T){
            w:=&liB05PartialTCPWriter{n:tc.n,err:tc.err}
            returned,gotErr:=WriteTCPRequest(w,method,[][]byte{psk},dest,salt,[]byte("data"))
            if returned!=nil {t.Fatal("short encrypted client handshake returned usable TCP writer")}
            if !errors.Is(gotErr,tc.want){t.Fatalf("client handshake error=%v, want %v",gotErr,tc.want)}
        })
    }
    // Outgoing server's original encrypted header+first user-data response.
    for _,tc:=range []struct{name string;n int;err error;want error}{
        {"server_zero",0,nil,io.ErrShortWrite},
        {"server_one",1,nil,io.ErrShortWrite},
        {"server_syscall",1,io.ErrClosedPipe,io.ErrClosedPipe},
    } {
        t.Run(tc.name,func(t *testing.T){
            w:=&liB05PartialTCPWriter{n:tc.n,err:tc.err}
            sw:=NewServerStreamWriter(w,method,psk,salt)
            n,gotErr:=sw.Write([]byte("original-downlink-payload"))
            if n!=0 {t.Fatalf("failed response first frame reported plaintext bytes=%d",n)}
            if !errors.Is(gotErr,tc.want){t.Fatalf("server first response error=%v want=%v",gotErr,tc.want)}
            if w.calls!=1 {t.Fatalf("original response socket calls=%d",w.calls)}
        })
    }
}
