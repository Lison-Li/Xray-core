package shadowsocks_2022

import (
    "errors"
    "io"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
)

// liB05NativeClientReceiptReader is implemented only by a caller-owned
// read-side DURABLE WAL reservation. Read must synchronously fsync its
// exact plaintext count before returning bytes. These methods are not
// synthetic accounting reports: only original encrypted net.Conn.Write
// success allows the caller to commit the pending ledger reservation.
type liB05NativeClientReceiptReader interface {
    io.Reader
    LiB05StrictClientConnReceipt() bool
    LiOnWriteAccepted(int32) error
    LiOnWriteFailed(error)
}

// liB05CopyNativeTCPOriginalWithReceipt preserves exact native SS2022
// framing, including first response header and authenticated AEAD payload.
// It never calls LiOnWriteAccepted on an internal Xray routing pipe.
func liB05CopyNativeTCPOriginalWithReceipt(r liB05NativeClientReceiptReader, original *ServerStreamWriter, onActivity func()) error {
    if r == nil || original == nil || !r.LiB05StrictClientConnReceipt() {
        return errors.New("B05 native TCP original socket receipt unavailable")
    }
    // One native AEAD chunk per reserve; a multi-chunk partial failure
    // cannot be mapped to a single exact confirmed plaintext size.
    plain := make([]byte, 32*1024)
    empty := 0
    for {
        n, readErr := r.Read(plain)
        if n < 0 || n > len(plain) {
            bad := errors.New("B05 invalid strict TCP client reader size")
            r.LiOnWriteFailed(bad)
            return bad
        }
        if n > 0 {
            if readErr != nil {
                r.LiOnWriteFailed(readErr)
                return readErr
            }
            // Hold the authenticated socket's deletion fence from BEFORE
            // the final physical Write through the final durable receipt.
            // The WAL reader has already reserved this plaintext chunk.
            // If an account was removed during Read, fail the outstanding
            // reservation instead of writing a post-revoke packet.
            binding := original.liB05NativeTCPBinding
            if binding != nil {
                binding.liB05ReceiptGate.RLock()
                if binding.liB05Revoked.Load() {
                    binding.liB05ReceiptGate.RUnlock()
                    r.LiOnWriteFailed(ErrInvalidRequest)
                    return ErrInvalidRequest
                }
            }
            wrote, writeErr := original.Write(plain[:n])
            if writeErr != nil {
                r.LiOnWriteFailed(writeErr)
                if binding != nil { binding.liB05ReceiptGate.RUnlock() }
                return writeErr
            }
            if wrote != n {
                r.LiOnWriteFailed(io.ErrShortWrite)
                if binding != nil { binding.liB05ReceiptGate.RUnlock() }
                return io.ErrShortWrite
            }
            if err := r.LiOnWriteAccepted(int32(n)); err != nil {
                r.LiOnWriteFailed(err)
                if binding != nil { binding.liB05ReceiptGate.RUnlock() }
                return err
            }
            if binding != nil { binding.liB05ReceiptGate.RUnlock() }
            if onActivity != nil { onActivity() }
            empty = 0
            continue
        }
        if readErr == io.EOF { return nil }
        if readErr != nil { return readErr }
        empty++
        if empty >= 8 {
            bad := io.ErrNoProgress
            r.LiOnWriteFailed(bad)
            return bad
        }
    }
}

// A packet reader's exact full batch was reserved in a real fsynced WAL
// before it supplied a buf.MultiBuffer. Confirm the entire plaintext
// batch ONCE, only after every encrypted native UDP socket Write succeeds.
// If any packet partially writes, the batch remains UNCERTAIN, never billed.
type liB05NativePacketReceiptReader interface {
    LiOnWriteAccepted(int32) error
    LiOnWriteFailed(error)
}

func liB05WriteNativeUDPBatchWithReceipt(
    s *ServerUDPSession,
    mb buf.MultiBuffer,
    fallback net.Destination,
    encode func(net.Destination, []byte) ([]byte, error),
    source buf.Reader,
) error {
    if s == nil { buf.ReleaseMulti(mb); return errors.New("B05 nil native UDP original session") }
    receipt, metered := source.(liB05NativePacketReceiptReader)
    expected := mb.Len()
    if metered && expected <= 0 {
        bad := errors.New("B05 strict native UDP reader returned empty reserved batch")
        receipt.LiOnWriteFailed(bad)
        buf.ReleaseMulti(mb)
        return bad
    }
    if metered {
        // Keep all datagrams from the same durable reservation and their
        // ONE final WAL callback in a single revoke-aware critical section.
        // Do NOT reuse writeGate: WriteToClient also takes its RLock, and
        // a pending exclusive RemoveUser could deadlock a recursive RLock.
        s.liB05ReceiptGate.RLock()
        defer s.liB05ReceiptGate.RUnlock()
        if s.revoked.Load() {
            receipt.LiOnWriteFailed(ErrInvalidRequest)
            buf.ReleaseMulti(mb)
            return ErrInvalidRequest
        }
    }
    for idx, b := range mb {
        payload := b.Bytes()
        if encode != nil {
            reply := fallback
            if b.UDP != nil { reply = *b.UDP }
            encrypted, err := encode(reply, payload)
            b.Release()
            if err != nil {
                if metered {
                    receipt.LiOnWriteFailed(err)
                    buf.ReleaseMulti(mb[idx+1:])
                    return err
                }
                continue
            }
            if err := s.WriteToClient(encrypted); err != nil {
                if metered { receipt.LiOnWriteFailed(err) }
                buf.ReleaseMulti(mb[idx+1:])
                return err
            }
        } else {
            err := s.WriteToClient(payload)
            b.Release()
            if err != nil {
                if metered { receipt.LiOnWriteFailed(err) }
                buf.ReleaseMulti(mb[idx+1:])
                return err
            }
        }
    }
    if metered {
        if err := receipt.LiOnWriteAccepted(expected); err != nil {
            receipt.LiOnWriteFailed(err)
            return err
        }
    }
    return nil
}
