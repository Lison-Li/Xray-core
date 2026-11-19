package shadowsocks_2022

import (
    "errors"
    "io"
    "testing"

    B "github.com/sagernet/sing/common/buf"
    "github.com/sagernet/sing/common/bufio"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
)

// The real overseas Action #44481612977 reached SS2022 UDP origin but
// panicked in sing-shadowsocks shadowaead_2022.serverPacketWriter:
// sing.buf.Buffer.ExtendHeader(42), start=0. The original encrypted Writer
// exposes FrontHeadroom/RearHeadroom via sing's NAT .Upstream() chain.
// Our newly inserted WAL Writer wrapper must transparently carry precisely
// that headroom through N.Calculate* before bufio.CopyPacketWithPool reads.
type b05SS2022OneActualCopyPacketReader struct {
    payload []byte
    sent bool
}
func (r *b05SS2022OneActualCopyPacketReader) ReadPacket(p *B.Buffer)(M.Socksaddr,error){
    if r.sent {return M.Socksaddr{},io.EOF}
    r.sent=true
    if _,err:=p.Write(r.payload);err!=nil{return M.Socksaddr{},err}
    return M.Socksaddr{},nil
}

type b05SS2022ActualHeaderSpaceWriter struct{
    N.PacketConn
    downstream any
    writes int
    observedFront int
    observedPayload int
}
func (p *b05SS2022ActualHeaderSpaceWriter) Upstream() any {return p.downstream}
func (p *b05SS2022ActualHeaderSpaceWriter) WritePacket(b *B.Buffer,_ M.Socksaddr)error{
    p.writes++
    p.observedFront=b.Start()
    p.observedPayload=b.Len()
    // Exact originally observed panic: sing-shadowsocks appends a 42-byte
    // encrypted header BEFORE the payload, plus 16-byte AEAD trailer.
    // This test uses the real sing buffer/CopyPacketWithPool implementation,
    // without a mocked success report from a fake encrypted client.
    if b.Start()<42 {return errors.New("B05 original encrypted SS2022 Writer received no reserved front headroom")}
    header:=b.ExtendHeader(42)
    for n:=range header {header[n]=0}
    trailer:=b.Extend(16)
    for n:=range trailer {trailer[n]=0}
    b.Release()
    return nil
}

func TestB05SS2022NativeActualSingCopyPacketPreservesEncryptedHeaderSpaceAndPlainWALBytes(t *testing.T){
    b05SS2022NativeOriginalTestFlags(t)
    // This is the actual sing-shadowsocks writer object that carries the
    // negotiated per-cipher front & rear headroom. Its Upstream() in real
    // service is reached via sing/common/udpnat.(*conn).Upstream().
    realEncryptedWriter:=&serverPacketWriter{Service:&Service{}}
    expectedFront:=N.CalculateFrontHeadroom(realEncryptedWriter)
    expectedRear:=N.CalculateRearHeadroom(realEncryptedWriter)
    if expectedFront<42 || expectedRear<16 {
        t.Fatalf("upstream source version changed SS2022 encrypted envelope: front=%d rear=%d",expectedFront,expectedRear)
    }
    original:=&b05SS2022ActualHeaderSpaceWriter{downstream:realEncryptedWriter}
    receipt:=&b05SS2022OriginalReceiptProbe{}
    wrapped,err:=liB05SS2022NativeUDPWrapOriginal(b05SS2022NativeOriginalTestContext(),receipt,original)
    if err!=nil {t.Fatal(err)}
    gotFront:=N.CalculateFrontHeadroom(wrapped)
    gotRear:=N.CalculateRearHeadroom(wrapped)
    if gotFront!=expectedFront || gotRear!=expectedRear {
        t.Fatalf("B05 original socket WAL wrapper HID required encrypted header/trailer: got %d/%d, want %d/%d",
            gotFront,gotRear,expectedFront,expectedRear)
    }
    originalBytes:=[]byte("real-ss2022-udp-reply-24")
    source:=&b05SS2022OneActualCopyPacketReader{payload:originalBytes}
    n,err:=bufio.CopyPacketWithPool(source,wrapped,source,nil,nil,false)
    if !errors.Is(err,io.EOF) {
        t.Fatalf("real sing packet copy did not finish after one packet: n=%d err=%v",n,err)
    }
    if n!=int64(len(originalBytes)) || original.writes!=1 ||
        original.observedFront!=expectedFront ||
        original.observedPayload!=len(originalBytes) {
        t.Fatalf("real native packet copy used wrong envelope/size: n=%d writes=%d front=%d payload=%d",
            n,original.writes,original.observedFront,original.observedPayload)
    }
    if len(receipt.accepted)!=1 || receipt.accepted[0]!=int32(len(originalBytes)) ||
        len(receipt.failed)!=0 {
        t.Fatalf("UDP encrypted Writer callback altered actual plaintext WAL count or order: %+v",receipt)
    }
    t.Log("B05_SS2022_ACTUAL_SING_PACKET_COPY_HEADROOM_42_AND_16_ORIGINAL_WRITER_PLAINTEXT_WAL_BYTES=PASS_UNIT_REGRESSION")
}
