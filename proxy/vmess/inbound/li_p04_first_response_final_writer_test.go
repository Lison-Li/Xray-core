package inbound

import (
    "io"
    "testing"

    "github.com/xtls/xray-core/common/buf"
)

// A real strict Writer-metered Reader must skip VMess's first-packet
// optimization, because it reserves bytes before returning them and only
// buf.Copy can trigger the actual linked post-Writer acceptance callback.
type liVMessQATestPlainReader struct{}
func (*liVMessQATestPlainReader) ReadMultiBuffer()(buf.MultiBuffer,error){return nil,io.EOF}
type liVMessQATestMeteredReader struct{liVMessQATestPlainReader}
func (*liVMessQATestMeteredReader) LiOnWriteAccepted(int32) error{return nil}
func (*liVMessQATestMeteredReader) LiOnWriteFailed(error){}

type liVMessQATestIncompleteReader struct{liVMessQATestPlainReader}
func (*liVMessQATestIncompleteReader) LiOnWriteAccepted(int32) error{return nil}

func TestVMessFirstDownlinkReservationUsesRealFinalCopyCallback(t *testing.T){
    if liVMessHasFinalWriterReceipt(&liVMessQATestPlainReader{}){
        t.Fatal("ordinary VMess illegally opted into strict callback path")
    }
    if liVMessHasFinalWriterReceipt(&liVMessQATestIncompleteReader{}){
        t.Fatal("an incomplete receipt must never be an accepted writer contract")
    }
    if !liVMessHasFinalWriterReceipt(&liVMessQATestMeteredReader{}){
        t.Fatal("verified accepted + failed callback Reader lost its final Copy receipt")
    }
}
