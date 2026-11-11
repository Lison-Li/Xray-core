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

func liB05MaybeWrapClientConn(reader buf.Reader, conn net.Conn) net.Conn {
    if os.Getenv("XRAYR_LI_B05_STRICT")!="1" ||
        os.Getenv("XRAYR_LI_B05_UNTAGGED_PREVIEW_LOOPBACK")!="1" ||
        os.Getenv("XRAYR_LI_P04_UNTAGGED_SS2022_TCP_PREVIEW_LOOPBACK")!="1" ||
        os.Getenv("XRAYR_LI_B05_SS2022_TCP_QA")!="1" ||
        os.Getenv("XRAYR_LI_B05_VLESS_TCP_QA")=="1" ||
        os.Getenv("XRAYR_LI_B05_LEGACY_SS_TCP_QA")=="1" ||
        os.Getenv("XRAYR_LI_B05_HY2_QUIC_QA")=="1" ||
        os.Getenv("XRAYR_LI_P04_UNTAGGED_VMESS_TCP_PREVIEW_LOOPBACK")=="1" ||
        os.Getenv("XRAYR_LI_P04_UNTAGGED_VMESS_WS_PREVIEW_LOOPBACK")=="1" ||
        os.Getenv("XRAYR_LI_P04_UNTAGGED_VMESS_GRPC_PREVIEW_LOOPBACK")=="1" {
        return conn
    }
    receipt,ok:=reader.(liB05ClientReceipt)
    if !ok || !receipt.LiB05StrictClientConnReceipt() {return conn}
    return &liB05QAClientProofConn{Conn:conn,receipt:receipt}
}
