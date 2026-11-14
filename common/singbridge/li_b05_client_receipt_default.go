//go:build !b05writerqa

package singbridge

// Untagged SS2022 encrypted-client final Writer callback is deliberately
// opt-in for isolated, strict IPv4-loopback QA only. Ordinary users and
// unpatched default processes continue to use exactly the original conn.
import (
    "net"
    "os"

    "github.com/xtls/xray-core/common/buf"
)

// This symbol makes an original-core-without-this-hook fail to compile
// against the guarded experimental XrayR-Li preview, never silently bill.
func LiB05UntaggedSS2022ClientReceiptHookReady() bool { return true }

// The ordinary 13-native run has a DIFFERENT, independent QA admission
// capability from the old single-SS2022 loopback staging. Never require the
// mutually exclusive single-mode flags just to receive the actual encrypted
// client socket Write callback. Do not accept merely the all13 opt-in: the
// lower-Writer ACK flag and all historical multi-node capability switches
// are mandatory, with the actual per-node user/tag guarded in XrayR's Dispatch.
func liB05All13NativeSS2022ClientReceiptEligible() bool {
    for _, k:=range []string{
        "XRAYR_LI_B05_STRICT",
        "XRAYR_LI_B05_PUBLIC_MULTI_NODE",
        "XRAYR_LI_B05_PUBLIC_MULTI_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_WS_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_WS_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_GRPC_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_VLESS_GRPC_WRITER_ACK",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_QA",
        "XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_WRITER_ACK",
    } {
        if os.Getenv(k)!="1" {return false}
    }
    // Never silently downgrade from the existing isolated single mode.
    for _, k:=range []string{
        "XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_B05_SS2022_TCP_QA",
        "XRAYR_LI_B05_VLESS_TCP_QA",
        "XRAYR_LI_B05_LEGACY_SS_TCP_QA",
        "XRAYR_LI_B05_HY2_QUIC_QA",
        "XRAYR_LI_P04_UNTAGGED_VMESS_TCP_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_WS_PREVIEW_LOOPBACK",
        "XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK",
    } {
        if os.Getenv(k)=="1" {return false}
    }
    return true
}
func liB05LegacySingleSS2022ClientReceiptEligible() bool {
    return os.Getenv("XRAYR_LI_B05_STRICT")=="1" &&
        os.Getenv("XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK")=="1" &&
        os.Getenv("XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK")=="1" &&
        os.Getenv("XRAYR_LI_B05_SS2022_TCP_QA")=="1" &&
        os.Getenv("XRAYR_LI_B05_VLESS_TCP_QA")!="1" &&
        os.Getenv("XRAYR_LI_B05_LEGACY_SS_TCP_QA")!="1" &&
        os.Getenv("XRAYR_LI_B05_HY2_QUIC_QA")!="1" &&
        os.Getenv("XRAYR_LI_P04_UNTAGGED_VMESS_TCP_PREVIEW_LOOPBACK")!="1" &&
        os.Getenv("XRAYR_LI_P04_UNTAGGED_VMESS_WS_PREVIEW_LOOPBACK")!="1" &&
        os.Getenv("XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK")!="1"
}
func liB05MaybeWrapClientConn(reader buf.Reader, conn net.Conn) net.Conn {
    if !liB05LegacySingleSS2022ClientReceiptEligible() &&
        !liB05All13NativeSS2022ClientReceiptEligible() {return conn}
    receipt,ok:=reader.(liB05ClientReceipt)
    if !ok || !receipt.LiB05StrictClientConnReceipt() {return conn}
    return &liB05QAClientProofConn{Conn:conn,receipt:receipt}
}
