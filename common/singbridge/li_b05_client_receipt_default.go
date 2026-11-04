//go:build !b05writerqa

package singbridge

import (
    "net"

    "github.com/xtls/xray-core/common/buf"
)

// The untagged/release build does not install a B05 client-side receipt
// adapter. Strict B05 admission remains separately fail-closed in XrayR-Li.
func liB05MaybeWrapClientConn(_ buf.Reader, conn net.Conn) net.Conn {
    return conn
}
