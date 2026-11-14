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

func TestLiB05All13NativeFinalClientConnWriterProofFailsClosedExceptFullDualGates(t *testing.T) {
    // Real #43572496570: SS2022 AES128/256 each reserved 3 WAL intents,
    // only two confirms, leaving real encrypted clients truncated. All13
    // had disabled the old mutually exclusive single-protocol runtime flags,
    // so the pinned core returned an UNWRAPPED net.Conn. Verify its actual
    // Write callback rather than asserting a simulated ACK.
    flags:=[]string{
        "XRAYR_LI_B05_STRICT",
        "XRAYR_LI_B05_PUBLIC_MULTI_NODE",
        "XRAYR_LI_B05_PUBLIC_MULTI_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_WS_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_WS_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_GRPC_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_GRPC_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_WRITER_ACK",
    }
    for _,flag:=range flags {t.Setenv(flag,"1")}
    for _,flag:=range []string{
        "XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_B05_SS2022_TCP_QA",
        "XRAYR_LI_B05_VLESS_TCP_QA",
        "XRAYR_LI_B05_LEGACY_SS_TCP_QA",
        "XRAYR_LI_B05_HY2_QUIC_QA",
        "XRAYR_LI_P04_UNTAGGED_VMESS_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_WS_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK",
    } {t.Setenv(flag,"0")}
    if !liB05All13NativeSS2022ClientReceiptEligible() {t.Fatal("actual 13-native all-ack flag denied")}
    probe:=func(t *testing.T,enabled bool) {
        t.Helper()
        a,b:=net.Pipe()
        defer a.Close()
        defer b.Close()
        marker:=&b05OrdinarySS2022ProofReader{ready:true}
        wrapped:=liB05MaybeWrapClientConn(marker,a)
        if enabled==(wrapped==a) {t.Fatalf("13-native proof wrapper active=%v required=%v",wrapped!=a,enabled)}
        payload:=[]byte("real encrypted Write receipt")
        done:=make(chan error,1)
        go func() {p:=make([]byte,len(payload));_,err:=io.ReadFull(b,p);done<-err}()
        n,err:=wrapped.Write(payload)
        if err!=nil || n!=len(payload) {t.Fatalf("real net.Pipe.Write failed %v",err)}
        if err=<-done;err!=nil {t.Fatal(err)}
        if enabled {
            if marker.accepted!=1 || marker.failed!=0 || marker.bytes!=int32(len(payload)) {
                t.Fatal("all13 real encrypted socket Write missed exactly one receipt")
            }
        } else if marker.accepted!=0 || marker.failed!=0 {
            t.Fatal("incomplete gate generated fake encrypted client receipt")
        }
    }
    t.Run("real_all13_native_conn_write",func(t *testing.T){probe(t,true)})
    for _,flag:=range flags {
        t.Run("missing_"+flag,func(t *testing.T){
            t.Setenv(flag,"0")
            if liB05All13NativeSS2022ClientReceiptEligible() {t.Fatal("partial gate succeeded")}
            probe(t,false)
        })
    }
    for _,flag:=range []string{
        "XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_B05_SS2022_TCP_QA",
        "XRAYR_LI_B05_LEGACY_SS_TCP_QA",
        "XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK",
    } {
        t.Run("mixed_"+flag,func(t *testing.T){
            t.Setenv(flag,"1")
            if liB05All13NativeSS2022ClientReceiptEligible(){t.Fatal("mixed native proof gate succeeded")}
            probe(t,false)
        })
    }
    t.Run("unmarked_reader",func(t *testing.T){
        a,b:=net.Pipe();defer a.Close();defer b.Close()
        if liB05MaybeWrapClientConn(&b05OrdinarySS2022ProofReader{ready:false},a)!=a {
            t.Fatal("unmarked plaintext reader claimed client Writer ACK")
        }
    })
    t.Log("B05_ALL13_SS2022_REAL_ENCRYPTED_CLIENT_WRITE_CALLBACK_DUAL_ACK_9_NEGATIVES=PASS")
}
