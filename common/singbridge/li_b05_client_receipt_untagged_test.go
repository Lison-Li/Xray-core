//go:build !b05writerqa

package singbridge

import (
    "bytes"
    "errors"
    "io"
    "net"
    "testing"

    "github.com/xtls/xray-core/common/buf"
)

type b05OrdinarySS2022ProofReader struct {
    accepted, failed int
    bytes int32
    ready bool
}
func (r *b05OrdinarySS2022ProofReader) ReadMultiBuffer()(buf.MultiBuffer,error){return nil,io.EOF}
func (r *b05OrdinarySS2022ProofReader) LiB05StrictClientConnReceipt()bool{return r.ready}
func (r *b05OrdinarySS2022ProofReader) LiOnWriteAccepted(n int32)error{r.accepted++;r.bytes=n;return nil}
func (r *b05OrdinarySS2022ProofReader) LiOnWriteFailed(error){r.failed++}

func b05SS2022PreviewEnv(t *testing.T){
    t.Helper()
    t.Setenv("XRAYR_LI_B05_STRICT","1")
    t.Setenv("XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK","1")
    t.Setenv("XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK","1")
    t.Setenv("XRAYR_LI_B05_SS2022_TCP_QA","1")
    for _,name:=range []string{
        "XRAYR_LI_B05_VLESS_TCP_QA","XRAYR_LI_B05_LEGACY_SS_TCP_QA",
        "XRAYR_LI_B05_HY2_QUIC_QA",
        "XRAYR_LI_P04_UNTAGGED_VMESS_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_WS_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK",
    } {t.Setenv(name,"0")}
}

func TestLiB05UntaggedSS2022MustKeepRealClientProofDisabledByDefault(t *testing.T){
    b05SS2022PreviewEnv(t)
    if !LiB05UntaggedSS2022ClientReceiptHookReady(){t.Fatal("no linked core capability")}
    blockers:=[]string{"XRAYR_LI_B05_STRICT","XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK","XRAYR_LI_B05_SS2022_TCP_QA"}
    for _,name:=range blockers{
        t.Run(name,func(t *testing.T){
            t.Setenv(name,"0")
            reader:=&b05OrdinarySS2022ProofReader{ready:true}
            a,b:=net.Pipe();defer a.Close();defer b.Close()
            if liB05MaybeWrapClientConn(reader,a)!=a {t.Fatal("untagged SS2022 callback enabled without all exact gates")}
        })
    }
    for _,name:=range []string{"XRAYR_LI_B05_VLESS_TCP_QA","XRAYR_LI_B05_LEGACY_SS_TCP_QA",
        "XRAYR_LI_B05_HY2_QUIC_QA","XRAYR_LI_P04_UNTAGGED_VMESS_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_WS_PREVIEW_LOOPBACK","XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK"}{
        t.Run(name,func(t *testing.T){
            t.Setenv(name,"1")
            reader:=&b05OrdinarySS2022ProofReader{ready:true}
            a,b:=net.Pipe();defer a.Close();defer b.Close()
            if liB05MaybeWrapClientConn(reader,a)!=a {t.Fatal("mixed protocol enabled SS2022 callback")}
        })
    }
}

func TestLiB05UntaggedSS2022RealNetConnWriteOrderAndMarker(t *testing.T){
    b05SS2022PreviewEnv(t)
    a,b:=net.Pipe();defer a.Close();defer b.Close()
    marker:=&b05OrdinarySS2022ProofReader{ready:true}
    guarded:=liB05MaybeWrapClientConn(marker,a)
    if guarded==a {t.Fatal("explicit protected writer was not instrumented")}
    payload:=[]byte("real encrypted client Write boundary")
    result:=make(chan []byte,1)
    go func(){p:=make([]byte,len(payload));n,err:=io.ReadFull(b,p);if err!=nil{result<-nil}else{result<-p[:n]}}()
    n,err:=guarded.Write(payload)
    if err!=nil||n!=len(payload){t.Fatalf("real socket write failed: %v",err)}
    if got:=<-result;!bytes.Equal(got,payload){t.Fatal("real peer socket did not receive verified bytes")}
    if marker.accepted!=1||marker.failed!=0||marker.bytes!=int32(len(payload)){t.Fatal("real net.Conn Write did not trigger exact post-write callback")}
    a2,b2:=net.Pipe();defer a2.Close();defer b2.Close()
    if liB05MaybeWrapClientConn(&b05OrdinarySS2022ProofReader{ready:false},a2)!=a2 {t.Fatal("unmarked reader permitted client proof")}
    if liB05MaybeWrapClientConn(buf.NewReader(bytes.NewReader(nil)),a2)!=a2 {t.Fatal("ordinary reader permitted client proof")}
}

type b05OrdinarySS2022ShortConn struct{net.Conn}
func (*b05OrdinarySS2022ShortConn)Write(p []byte)(int,error){return len(p)-1,nil}
func TestLiB05UntaggedSS2022ShortClientWriteFailsClosed(t *testing.T){
    b05SS2022PreviewEnv(t)
    a,b:=net.Pipe();defer a.Close();defer b.Close()
    reader:=&b05OrdinarySS2022ProofReader{ready:true}
    wrapped:=liB05MaybeWrapClientConn(reader,&b05OrdinarySS2022ShortConn{a})
    _,err:=wrapped.Write([]byte("short"))
    if !errors.Is(err,io.ErrShortWrite){t.Fatalf("missing true short-Write failure: %v",err)}
    if reader.accepted!=0||reader.failed!=1{t.Fatal("short encrypted client Write was falsely confirmed")}
}
