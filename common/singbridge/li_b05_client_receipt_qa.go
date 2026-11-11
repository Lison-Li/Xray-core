//go:build b05writerqa

package singbridge

// Preserve the original QA-tagged SS2022 callback selection unchanged.
import (
    "net"
    "github.com/xtls/xray-core/common/buf"
)
func liB05MaybeWrapClientConn(reader buf.Reader, conn net.Conn) net.Conn {
    if receipt, ok := reader.(liB05ClientReceipt); ok && receipt.LiB05StrictClientConnReceipt() {
        return &liB05QAClientProofConn{Conn:conn,receipt:receipt}
    }
    return conn
}
