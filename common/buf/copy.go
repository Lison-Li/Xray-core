package buf

import (
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
)

type dataHandler func(MultiBuffer)

type copyHandler struct {
	onData []dataHandler
}

// SizeCounter is for counting bytes copied by Copy().
type SizeCounter struct {
	Size int64
}

// CopyOption is an option for copying data.
type CopyOption func(*copyHandler)

// UpdateActivity is a CopyOption to update activity on each data copy operation.
func UpdateActivity(timer signal.ActivityUpdater) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(MultiBuffer) {
			timer.Update()
		})
	}
}

// CountSize is a CopyOption that sums the total size of data copied into the given SizeCounter.
func CountSize(sc *SizeCounter) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(b MultiBuffer) {
			sc.Size += int64(b.Len())
		})
	}
}

// AddToStatCounter a CopyOption add to stat counter
func AddToStatCounter(sc stats.Counter) CopyOption {
	return func(handler *copyHandler) {
		handler.onData = append(handler.onData, func(b MultiBuffer) {
			if sc != nil {
				sc.Add(int64(b.Len()))
			}
		})
	}
}

type readError struct {
	error
}

func (e readError) Error() string {
	return e.error.Error()
}

func (e readError) Unwrap() error {
	return e.error
}

// IsReadError returns true if the error in Copy() comes from reading.
func IsReadError(err error) bool {
	_, ok := err.(readError)
	return ok
}

type writeError struct {
	error
}

func (e writeError) Error() string {
	return e.error.Error()
}

func (e writeError) Unwrap() error {
	return e.error
}

// IsWriteError returns true if the error in Copy() comes from writing.
func IsWriteError(err error) bool {
	_, ok := err.(writeError)
	return ok
}

func copyInternal(reader Reader, writer Writer, handler *copyHandler) error {
	for {
		buffer, err := reader.ReadMultiBuffer()
		if !buffer.IsEmpty() {
			for _, handler := range handler.onData {
				handler(buffer)
			}

			// A B05 metered Reader reserves/fsyncs bytes before this call.
			// Only the return of the delegated Writer can confirm delivery.
			acceptedSize := buffer.Len()
			if werr := liB05SafeFinalWriterCall(reader, writer, buffer); werr != nil {
				if receipt, ok := reader.(interface{ LiOnWriteFailed(error) }); ok {
					receipt.LiOnWriteFailed(werr)
				}
				return writeError{werr}
			}
			if receipt, ok := reader.(interface{ LiOnWriteAccepted(int32) error }); ok {
				if aerr := receipt.LiOnWriteAccepted(acceptedSize); aerr != nil {
					return writeError{aerr}
				}
			}
		}

		if err != nil {
			return readError{err}
		}
	}
}

// Copy dumps all payload from reader to writer or stops when an error occurs. It returns nil when EOF.
func Copy(reader Reader, writer Writer, options ...CopyOption) error {
	var handler copyHandler
	for _, option := range options {
		option(&handler)
	}
	err := copyInternal(reader, writer, &handler)
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

var ErrNotTimeoutReader = errors.New("not a TimeoutReader")

func CopyOnceTimeout(reader Reader, writer Writer, timeout time.Duration) error {
	timeoutReader, ok := reader.(TimeoutReader)
	if !ok {
		return ErrNotTimeoutReader
	}
	mb, err := timeoutReader.ReadMultiBufferTimeout(timeout)
	if err != nil {
		return err
	}
	acceptedSize := mb.Len()
	if err := liB05SafeFinalWriterCall(reader, writer, mb); err != nil {
		if receipt, ok := reader.(interface{ LiOnWriteFailed(error) }); ok {
			receipt.LiOnWriteFailed(err)
		}
		return err
	}
	if receipt, ok := reader.(interface{ LiOnWriteAccepted(int32) error }); ok {
		return receipt.LiOnWriteAccepted(acceptedSize)
	}
	return nil
}


// liB05SafeFinalWriterCall preserves unknown partial deliveries. Never
// refund or forge a receipt when a delegate panics after taking ownership.
func liB05SafeFinalWriterCall(reader Reader, writer Writer, mb MultiBuffer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if receipt, ok := reader.(interface{ LiOnWriteFailed(error) }); ok {
				receipt.LiOnWriteFailed(errors.New("B05 final Writer panic: delivery unknown"))
			}
			panic(recovered)
		}
	}()
	return writer.WriteMultiBuffer(mb)
}
