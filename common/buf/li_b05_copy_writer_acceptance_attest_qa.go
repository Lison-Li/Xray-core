//go:build b05writerqa

package buf

// LiCopyWriterAcceptanceHookReady is a QA-only compile-time attestation
// that this pinned fork contains the B05 Copy/CopyOnceTimeout callback.
// The callback acknowledges bytes only after the delegated Writer returns
// success; errors and panics retain the existing fail-closed semantics.
//
// This does NOT certify that a particular Writer is the final socket writer,
// nor does it enable production strict billing. The classic SS first-flush
// contract and the real-client WAL/D1 checks must still pass separately.
func LiCopyWriterAcceptanceHookReady() bool { return true }
