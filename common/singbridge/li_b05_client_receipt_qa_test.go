//go:build b05writerqa

package singbridge

import (
    "net"
    "testing"
    "io"

    "github.com/xtls/xray-core/common/buf"
)

type b05QAPanicConn struct { net.Conn }
func (*b05QAPanicConn) Write([]byte) (int, error) { panic("QA encrypted client Write panic") }

type b05QAPanicReceipt struct { failed, confirmed int }
func (r *b05QAPanicReceipt) LiB05StrictClientConnReceipt() bool { return true }
func (r *b05QAPanicReceipt) LiOnWriteAccepted(int32) error { r.confirmed++; return nil }
func (r *b05QAPanicReceipt) LiOnWriteFailed(error) { r.failed++ }

func TestB05QAEncryptedClientConnWritePanicNotifiesAndRepanics(t *testing.T) {
    receipt := &b05QAPanicReceipt{}
    conn := liB05MaybeWrapClientConn(receiptReader{receipt}, &b05QAPanicConn{})
    recovered := false
    func() {
        defer func() { if recover() != nil { recovered = true } }()
        _, _ = conn.Write([]byte("abc"))
    }()
    if !recovered || receipt.failed != 1 || receipt.confirmed != 0 {
        t.Fatalf("panic must rethrow and quarantine once, recovered=%v failures=%d confirms=%d",
            recovered, receipt.failed, receipt.confirmed)
    }
    t.Log("B05_SS2022_ENCRYPTED_CLIENT_PANIC_NOTIFIES_FAILED_RECEIPT_AND_REPANICS=PASS")
}

// A minimal buf.Reader that exercises the actual QA-only selection path.
type receiptReader struct { *b05QAPanicReceipt }
func (receiptReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }
