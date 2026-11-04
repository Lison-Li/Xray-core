//go:build b05writerqa

package singbridge

// QA-only encrypted-client final Write receipt bridge. The core's ordinary
// untagged builds use the separate pass-through implementation instead.
import (
    "io"
    "net"

    "github.com/xtls/xray-core/common/buf"
)

type liB05ClientReceipt interface {
    LiB05StrictClientConnReceipt() bool
    LiOnWriteAccepted(int32) error
    LiOnWriteFailed(error)
}

func liB05MaybeWrapClientConn(reader buf.Reader, conn net.Conn) net.Conn {
    if receipt, ok := reader.(liB05ClientReceipt); ok && receipt.LiB05StrictClientConnReceipt() {
        return &liB05QAClientProofConn{Conn: conn, receipt: receipt}
    }
    return conn
}

// Only actual encrypted client net.Conn.Write completion may confirm
// bytes reserved/fsynced by the special SS2022 QA reader.
// A short/error/panic leaves WAL delivery uncertain, not billable.
type liB05QAClientProofConn struct {
    net.Conn
    receipt liB05ClientReceipt
}

func (c *liB05QAClientProofConn) liB05QASafeConnWrite(p []byte) (n int, err error) {
    defer func() {
        if recovered := recover(); recovered != nil {
            c.receipt.LiOnWriteFailed(io.ErrUnexpectedEOF)
            panic(recovered)
        }
    }()
    return c.Conn.Write(p)
}

func (c *liB05QAClientProofConn) Write(p []byte) (int, error) {
    n, err := c.liB05QASafeConnWrite(p)
    if err != nil || n != len(p) {
        if err == nil {
            err = io.ErrShortWrite
        }
        c.receipt.LiOnWriteFailed(err)
        return n, err
    }
    if err = c.receipt.LiOnWriteAccepted(int32(n)); err != nil {
        return n, err
    }
    return n, nil
}
