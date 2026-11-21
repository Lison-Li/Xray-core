package shadowsocks_2022

import (
    "context"
    "errors"
    "io"
    "testing"
    "strings"

    B "github.com/sagernet/sing/common/buf"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/session"
)

type b05SS2022OriginalReceiptProbe struct {
    accepted []int32
    failed []error
    acceptErr error
}
func (r *b05SS2022OriginalReceiptProbe) ReadMultiBuffer()(buf.MultiBuffer,error){return nil,io.EOF}
func (r *b05SS2022OriginalReceiptProbe) LiOnWriteAccepted(n int32)error{
    r.accepted=append(r.accepted,n)
    return r.acceptErr
}
func (r *b05SS2022OriginalReceiptProbe) LiOnWriteFailed(e error){r.failed=append(r.failed,e)}

type b05SS2022OriginalPacketConnProbe struct{
    N.PacketConn
    calls int
    err error
    mutatePacket bool
}
func (w *b05SS2022OriginalPacketConnProbe) WritePacket(p *B.Buffer,_ M.Socksaddr)error{
    w.calls++
    if w.mutatePacket {_,_ = p.Write([]byte("encrypted-salt-overhead"))}
    return w.err
}
func b05SS2022NativeOriginalTestContext()context.Context{
    return session.ContextWithInbound(context.Background(),&session.Inbound{
        Name:"shadowsocks-2022-multi",
        Tag:"Shadowsocks_127.0.0.1_23456",
        Source:net.Destination{Network:net.Network_UDP,
            Address:net.ParseAddress("127.0.0.1"),Port:54321},
        User:&protocol.MemoryUser{Email:"Shadowsocks_127.0.0.1_23456|qa-user@test.invalid|1"},
    })
}
func b05SS2022NativeOriginalTestFlags(t *testing.T) {
    t.Helper()
    for _,key:=range []string{
        "XRAYR_LI_B05_STRICT","XRAYR_LI_B05_PUBLIC_MULTI_NODE",
        "XRAYR_LI_B05_PUBLIC_MULTI_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_WRITER_ACK",
        "XRAYR_LI_B05_ALL13_UDP_TUNNEL_LOOPBACK_QA",
        "XRAYR_LI_B05_ALL13_UDP_TUNNEL_WRITER_ACK",
        "XRAYR_LI_B05_NATIVE_SS2022_UDP_QA",
        "XRAYR_LI_B05_NATIVE_SS2022_UDP_FINAL_WRITER_ACK",
    } {t.Setenv(key,"1")}
}

// This regression exercises the ACTUAL source-pinned upstream-fork native
// encrypted UDP Writer, not a Controller-level or Dispatcher-level imitation.
// The external real Mihomo test must independently prove actual packet arrival.
func TestB05SS2022NativePublicOriginalEncryptedWriterExactExternalSourceAndTwoFlags(t *testing.T) {
    b05SS2022NativeOriginalTestFlags(t)
    const pub="XRAYR_LI_B05_PUBLIC_SS2022_NATIVE_QA"
    const ack="XRAYR_LI_B05_PUBLIC_SS2022_NATIVE_WRITER_ACK"
    t.Setenv(pub,"0")
    t.Setenv(ack,"0")

    publicInbound:=func() *session.Inbound {
        return &session.Inbound{
            Name:"shadowsocks-2022-multi",
            Tag:"Shadowsocks_0.0.0.0_54687",
            Source:net.Destination{
                Network:net.Network_UDP,
                Address:net.ParseAddress("8.8.8.8"),Port:34687,
            },
            User:&protocol.MemoryUser{Email:"Shadowsocks_0.0.0.0_54687|qa-user@test.invalid|1"},
        }
    }
    accept:=func(in *session.Inbound)error {
        ctx:=session.ContextWithInbound(context.Background(),in)
        r:=&b05SS2022OriginalReceiptProbe{}
        c:=&b05SS2022OriginalPacketConnProbe{mutatePacket:true}
        wrapped,err:=liB05SS2022NativeUDPWrapOriginal(ctx,r,c)
        if err!=nil {return err}
        if wrapped==c{return io.ErrClosedPipe}
        payload:=B.As([]byte("original-udp-public-qa-24"))
        originalSize:=int32(payload.Len())
        if err:=wrapped.WritePacket(payload,M.Socksaddr{});err!=nil{return err}
        if c.calls!=1 || len(r.accepted)!=1 || r.accepted[0]!=originalSize || len(r.failed)!=0 {
            return io.ErrShortWrite
        }
        return nil
    }
    reject:=func(name string,in *session.Inbound){
        t.Helper()
        if err:=accept(in);err==nil {
            t.Fatalf("unverified external original encrypted UDP Writer admitted: %s",name)
        }
    }
    reject("default-disabled",publicInbound())
    t.Setenv(pub,"1")
    reject("first-optin-only",publicInbound())
    t.Setenv(pub,"0")
    t.Setenv(ack,"1")
    reject("second-optin-only",publicInbound())
    // Public approval must NOT be a blanket bypass for the old loopback
    // source; the exact canonical public listener and a routable source
    // are mandatory for the old lower original post-socket receipt.
    t.Setenv(pub,"1")
    if err:=accept(publicInbound());err!=nil {
        t.Fatalf("real authenticated external SS2022 UDP post-socket Writer refused: %v",err)
    }

    malformed:=[]struct{
        name string
        alter func(*session.Inbound)
    }{
        {"wrong-2022-identity",func(i *session.Inbound){i.Name="shadowsocks-2022-relay"}},
        {"wrong-node-tag",func(i *session.Inbound){i.Tag="Shadowsocks_0.0.0.0_54688"}},
        {"private-tag",func(i *session.Inbound){i.Tag="Shadowsocks_127.0.0.1_54687"}},
        {"fake-leading-zero",func(i *session.Inbound){i.Tag="Shadowsocks_0.0.0.0_054687"}},
        {"public-ipv6",func(i *session.Inbound){i.Source.Address=net.ParseAddress("2001:4860:4860::8888")}},
        {"loopback-client",func(i *session.Inbound){i.Source.Address=net.ParseAddress("127.0.0.1")}},
        {"private-client",func(i *session.Inbound){i.Source.Address=net.ParseAddress("192.168.1.8")}},
        {"link-local-client",func(i *session.Inbound){i.Source.Address=net.ParseAddress("169.254.1.8")}},
        {"empty-source",func(i *session.Inbound){i.Source.Address=nil}},
        {"missing-port",func(i *session.Inbound){i.Source.Port=0}},
        {"wrong-network",func(i *session.Inbound){i.Source.Network=net.Network_TCP}},
        {"missing-user",func(i *session.Inbound){i.User=nil}},
        {"missing-user-identity",func(i *session.Inbound){i.User.Email=""}},
    }
    for _,tc:=range malformed {
        t.Run(tc.name,func(t *testing.T){
            in:=publicInbound();tc.alter(in)
            reject(tc.name,in)
        })
    }
    for _,flag:=range []string{
        "XRAYR_LI_B05_STRICT",
        "XRAYR_LI_B05_PUBLIC_MULTI_NODE",
        "XRAYR_LI_B05_PUBLIC_MULTI_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_WRITER_ACK",
        "XRAYR_LI_B05_ALL13_UDP_TUNNEL_LOOPBACK_QA",
        "XRAYR_LI_B05_ALL13_UDP_TUNNEL_WRITER_ACK",
        "XRAYR_LI_B05_NATIVE_SS2022_UDP_QA",
        "XRAYR_LI_B05_NATIVE_SS2022_UDP_FINAL_WRITER_ACK",
    } {
        t.Run("missing-core-"+strings.TrimPrefix(flag,"XRAYR_LI_"),func(t *testing.T){
            t.Setenv(flag,"0")
            reject("missing-"+flag,publicInbound())
        })
    }
    // Keep original local source pathway identical without public opt-in.
    t.Setenv(pub,"0")
    t.Setenv(ack,"0")
    if err:=accept(session.InboundFromContext(b05SS2022NativeOriginalTestContext()));err!=nil {
        t.Fatalf("old genuinely authenticated strict loopback UDP broken: %v",err)
    }
    t.Log("B05_SS2022_CORE_PUBLIC_NATIVE_AES128_AES256_EXTERNAL_EXACT_ORIGINAL_UDP_PACKETCONN_WRITER_AND_2FLAGS=PASS_UNIT")
}

func TestB05SS2022NativeOriginalUDPFinalWriterRequiresPostPacketConnReceipt(t *testing.T) {
    b05SS2022NativeOriginalTestFlags(t)
    for _,tc:=range []struct{
        name string
        writerErr error
        receiptErr error
        wantAccepted int
        wantFailed int
    }{
        {"fully-original-packet-success",nil,nil,1,0},
        {"physical-packet-writer-failure",io.ErrShortWrite,nil,0,1},
        {"fsynced-ledger-confirm-failure",nil,io.ErrClosedPipe,1,1},
    } {
        t.Run(tc.name,func(t *testing.T){
            src:=&b05SS2022OriginalReceiptProbe{acceptErr:tc.receiptErr}
            original:=&b05SS2022OriginalPacketConnProbe{
                err:tc.writerErr,mutatePacket:true,
            }
            wrapped,err:=liB05SS2022NativeUDPWrapOriginal(b05SS2022NativeOriginalTestContext(),src,original)
            if err!=nil {t.Fatalf("exact private native UDP mode denied: %v",err)}
            if wrapped==original {t.Fatal("real original PacketConn not wrapped")}
            originalPayload:=B.As([]byte("exact-24-app-udp-bytes!"))
            wantBytes:=int32(originalPayload.Len())
            err=wrapped.WritePacket(originalPayload,M.Socksaddr{})
            if original.calls!=1 {t.Fatalf("original encrypted socket Writer calls=%d",original.calls)}
            if tc.writerErr!=nil && !errors.Is(err,tc.writerErr) {
                t.Fatalf("original failed socket result lost: %v",err)
            }
            if tc.receiptErr!=nil && !errors.Is(err,tc.receiptErr) {
                t.Fatalf("real fsync confirmation failure lost: %v",err)
            }
            if tc.writerErr==nil && tc.receiptErr==nil && err!=nil {t.Fatal(err)}
            if len(src.accepted)!=tc.wantAccepted||len(src.failed)!=tc.wantFailed {
                t.Fatalf("callback timing/count mismatch: accepted=%v failed=%v",src.accepted,src.failed)
            }
            if tc.wantAccepted>0 && src.accepted[0]!=wantBytes {
                t.Fatalf("counted encrypted bytes, not original application length: %v want %d",src.accepted,wantBytes)
            }
        })
    }
    t.Log("B05_SS2022_NATIVE_UDP_ORIGINAL_WRITER_CALLBACK_AFTER_PACKET_CONN_ONLY=PASS_UNIT_BOUNDARY_NOT_E2E")
}
func TestB05SS2022NativeOriginalUDPPartialFlagsAndForgedSourceFailClosed(t *testing.T) {
    b05SS2022NativeOriginalTestFlags(t)
    for _,key:=range []string{
        "XRAYR_LI_B05_STRICT",
        "XRAYR_LI_B05_PUBLIC_MULTI_NODE",
        "XRAYR_LI_B05_PUBLIC_MULTI_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_WRITER_ACK",
        "XRAYR_LI_B05_ALL13_UDP_TUNNEL_LOOPBACK_QA",
        "XRAYR_LI_B05_ALL13_UDP_TUNNEL_WRITER_ACK",
        "XRAYR_LI_B05_NATIVE_SS2022_UDP_QA",
        "XRAYR_LI_B05_NATIVE_SS2022_UDP_FINAL_WRITER_ACK",
    } {
        t.Run("missing-"+key,func(t *testing.T) {
            t.Setenv(key,"0")
            _,err:=liB05SS2022NativeUDPWrapOriginal(
                b05SS2022NativeOriginalTestContext(),
                &b05SS2022OriginalReceiptProbe{},
                &b05SS2022OriginalPacketConnProbe{},
            )
            if err==nil {t.Fatalf("partial native UDP flags %s incorrectly admitted",key)}
        })
    }
    for _,tc:=range []struct{
        name string
        mutate func(*session.Inbound)
    }{
        {"no-authenticated-user",func(in *session.Inbound){in.User=nil}},
        {"public-ipv4-peer",func(in *session.Inbound){in.Source.Address=net.ParseAddress("192.0.2.1")}},
        {"tcp-fake-peer",func(in *session.Inbound){in.Source.Network=net.Network_TCP}},
        {"wrong-protocol",func(in *session.Inbound){in.Name="shadowsocks"}},
        {"bad-tag",func(in *session.Inbound){in.Tag="Shadowsocks_0.0.0.0_23456"}},
        {"noncanonical-port",func(in *session.Inbound){in.Tag="Shadowsocks_127.0.0.1_023456"}},
    } {
        t.Run(tc.name,func(t *testing.T) {
            in:=*session.InboundFromContext(b05SS2022NativeOriginalTestContext())
            tc.mutate(&in)
            ctx:=session.ContextWithInbound(context.Background(),&in)
            _,err:=liB05SS2022NativeUDPWrapOriginal(ctx,&b05SS2022OriginalReceiptProbe{},
                &b05SS2022OriginalPacketConnProbe{})
            if err==nil {t.Fatal("forged native UDP session admitted")}
        })
    }
    _,err:=liB05SS2022NativeUDPWrapOriginal(b05SS2022NativeOriginalTestContext(),nil,
        &b05SS2022OriginalPacketConnProbe{})
    if err==nil {t.Fatal("missing real dispatcher meter receipt admitted")}
    t.Log("B05_SS2022_NATIVE_UDP_STRICT_AUTHENTICATED_SOURCE_AND_FLAG_FAILCLOSED=PASS_UNIT_GATE_NOT_E2E")
}
