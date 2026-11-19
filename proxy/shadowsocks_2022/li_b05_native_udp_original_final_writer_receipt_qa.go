package shadowsocks_2022

// This is a separately double-opted nonproduction adapter for the ORIGINAL
// SS2022 multi-user UDP response path. sing-shadowsocks encrypts the application
// packet and calls the original natPacketConn.WritePacket synchronously BEFORE
// its WritePacket returns to this adapter. Never acknowledge a dispatcher
// pipe Write, an encryption step, a test stub, or a successful decryption as
// a physical final client Writer receipt.
import (
    "context"
    "fmt"
    "math"
    "os"
    "strconv"
    "strings"

    B "github.com/sagernet/sing/common/buf"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
)

// Presence is a compile-time link check, NOT runtime proof of real encrypted
// client packets, exact per-UID WAL, revocation, or D1 atomic-v2 acceptance.
func LiB05SS2022NativeUDPOriginalSocketReceiptHookReady() bool { return true }

type liB05SS2022FinalUDPAcceptance interface {
    LiOnWriteAccepted(int32) error
    LiOnWriteFailed(error)
}

type liB05SS2022NativeOriginalFinalWriter struct {
    N.PacketConn
    receipt liB05SS2022FinalUDPAcceptance
}

func (c *liB05SS2022NativeOriginalFinalWriter) WritePacket(packet *B.Buffer, addr M.Socksaddr) (err error) {
    if c == nil || c.PacketConn == nil || c.receipt == nil ||
        packet == nil || packet.Len() <= 0 || packet.Len() > math.MaxInt32 {
        return fmt.Errorf("B05 SS2022 native UDP original encrypted Writer lacks valid packet or receipt")
    }
    // Capture exact plaintext application payload size BEFORE sing-shadowsocks
    // encrypts and adds salt/header/padding. The encrypted datagram is NOT
    // the billable size, and may modify packet contents.
    plaintextBytes := int32(packet.Len())
    defer func() {
        if recovered := recover(); recovered != nil {
            c.receipt.LiOnWriteFailed(fmt.Errorf("B05 SS2022 original encrypted UDP Writer panic; delivery ambiguous"))
            panic(recovered)
        }
    }()
    // Must execute the ORIGINAL authentication-linked sing PacketConn
    // synchronously. Its serverPacketWriter -> natPacketConn.WritePacket
    // reaches the real encrypted UDP socket and detects short writes.
    if err = c.PacketConn.WritePacket(packet,addr); err != nil {
        c.receipt.LiOnWriteFailed(err)
        return err
    }
    // Only this callback may fsync the original dispatcher reader's WAL
    // reservation for the exact authenticated user and payload byte count.
    if err = c.receipt.LiOnWriteAccepted(plaintextBytes); err != nil {
        c.receipt.LiOnWriteFailed(err)
        return err
    }
    return nil
}

func liB05SS2022NativeUDPOriginalRequested() bool {
    return os.Getenv("XRAYR_LI_B05_NATIVE_SS2022_UDP_QA")=="1" ||
        os.Getenv("XRAYR_LI_B05_NATIVE_SS2022_UDP_FINAL_WRITER_ACK")=="1"
}

// The regular SS2022 TCP-only mode is untouched. If a partial native UDP flag
// is present, do not silently fall back to unbilled native UDP networking.
func liB05SS2022NativeUDPWrapOriginal(ctx context.Context, reader buf.Reader, original N.PacketConn) (N.PacketConn,error) {
    if !liB05SS2022NativeUDPOriginalRequested() {return original,nil}
    fail := func()(N.PacketConn,error) {
        return nil,fmt.Errorf("B05 SS2022 native UDP denied before original client socket: exact strict authenticated localhost flags/receipt missing")
    }
    for _,key := range [...]string{
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
        if os.Getenv(key)!="1" {return fail()}
    }
    in := session.InboundFromContext(ctx)
    if in==nil || in.Name!="shadowsocks-2022-multi" ||
        in.User==nil || in.User.Email=="" ||
        in.Source.Network!=net.Network_UDP ||
        in.Source.Address==nil || in.Source.Address.String()!="127.0.0.1" ||
        in.Source.Port==0 || original==nil || reader==nil {
        return fail()
    }
    const prefix="Shadowsocks_127.0.0.1_"
    if !strings.HasPrefix(in.Tag,prefix) {return fail()}
    portText:=strings.TrimPrefix(in.Tag,prefix)
    port,err:=strconv.Atoi(portText)
    if err!=nil || port<1024 || port>65535 || strconv.Itoa(port)!=portText {return fail()}
    receipt,ok:=reader.(liB05SS2022FinalUDPAcceptance)
    if !ok {return fail()}
    return &liB05SS2022NativeOriginalFinalWriter{PacketConn:original,receipt:receipt},nil
}
