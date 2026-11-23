package buf

import (
	"errors"
	"io"
	"testing"
	"time"
)

type liB05CopyReceiptReader struct {
	pending    []byte
	called     bool
	accepted   []int32
	failed     []error
	failAccept error
}

func (r *liB05CopyReceiptReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.called {
		return nil, io.EOF
	}
	r.called = true
	b := New()
	b.Write(r.pending)
	return MultiBuffer{b}, nil
}

func (r *liB05CopyReceiptReader) ReadMultiBufferTimeout(time.Duration) (MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

func (r *liB05CopyReceiptReader) LiOnWriteAccepted(n int32) error {
	r.accepted = append(r.accepted, n)
	return r.failAccept
}
func (r *liB05CopyReceiptReader) LiOnWriteFailed(err error) { r.failed = append(r.failed, err) }

type liB05CopyPhysicalWriter struct {
	calls       int
	accepted    int32
	err         error
	panicBefore bool
}

func (w *liB05CopyPhysicalWriter) WriteMultiBuffer(mb MultiBuffer) error {
	w.calls++
	if w.panicBefore {
		panic("original-writer-panic")
	}
	w.accepted += mb.Len()
	ReleaseMulti(mb)
	return w.err
}

func TestB05ModernCoreOriginalCopyFinalWriterReceiptAndFailure(t *testing.T) {
	for _, c := range []struct {
		name         string
		failWrite    error
		failAccept   error
		wantAccepted int
		wantFailed   int
		wantErr      bool
	}{
		{"full_original_writer", nil, nil, 1, 0, false},
		{"failing_original_writer", io.ErrShortWrite, nil, 0, 1, true},
		{"durable_confirm_failure", nil, io.ErrClosedPipe, 1, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &liB05CopyReceiptReader{pending: []byte("canonical-plaintext"), failAccept: c.failAccept}
			w := &liB05CopyPhysicalWriter{err: c.failWrite}
			err := Copy(r, w)
			if (err != nil) != c.wantErr || len(r.accepted) != c.wantAccepted || len(r.failed) != c.wantFailed || w.calls != 1 {
				t.Fatalf("post Writer result err=%v calls=%d accepted=%v failed=%v", err, w.calls, r.accepted, r.failed)
			}
			if len(r.accepted) > 0 && r.accepted[0] != int32(len(r.pending)) {
				t.Fatal("wrong plaintext size")
			}
			if c.failWrite != nil && !errors.Is(err, c.failWrite) {
				t.Fatalf("original error not preserved: %v", err)
			}
			if c.failAccept != nil && !errors.Is(err, c.failAccept) {
				t.Fatalf("durable Confirm error not preserved: %v", err)
			}
		})
	}
}

func TestB05ModernCoreCopyOnceTimeoutFinalWriterReceipt(t *testing.T) {
	for _, c := range []struct {
		name    string
		err     error
		wantAck bool
	}{
		{"complete", nil, true}, {"writer-failed", io.ErrClosedPipe, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &liB05CopyReceiptReader{pending: []byte("one-time-original")}
			w := &liB05CopyPhysicalWriter{err: c.err}
			err := CopyOnceTimeout(r, w, 50*time.Millisecond)
			if (err != nil) != (c.err != nil) || (len(r.accepted) == 1) != c.wantAck || len(r.failed) != func() int {
				if c.err != nil {
					return 1
				}
				return 0
			}() {
				t.Fatalf("timeout Copy receipt: err=%v ack=%v failed=%v", err, r.accepted, r.failed)
			}
		})
	}
}

func TestB05ModernCoreCopyWriterPanicQuarantinesBeforeRepanic(t *testing.T) {
	r := &liB05CopyReceiptReader{pending: []byte("panic-after-ownership")}
	w := &liB05CopyPhysicalWriter{panicBefore: true}
	defer func() {
		if recover() == nil {
			t.Fatal("original writer panic swallowed")
		}
		if len(r.failed) != 1 || len(r.accepted) != 0 {
			t.Fatalf("panic delivery ambiguity not quarantined: failed=%v accepted=%v", r.failed, r.accepted)
		}
	}()
	_ = Copy(r, w)
}
