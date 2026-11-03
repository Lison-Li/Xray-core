//go:build b05writerqa && legacysswriterqa

// This file is copied ONLY into the pinned, temporary Xray-core module by
// qa/b05_legacy_ss_first_writer_overlay_20261103.py. It is an isolated
// component test, NOT real network / Cloudflare end-to-end evidence.
package shadowsocks

import (
    "errors"
    "io"
    "testing"

    "github.com/xtls/xray-core/common/buf"
)

type b05LegacyFlushProbe struct {
    payload []byte
    alreadyRead bool
    writer *b05LegacyFlushWriter
    acknowledgements []int32
    failures int
}

func (p *b05LegacyFlushProbe) ReadMultiBuffer()(buf.MultiBuffer,error){
    if p.alreadyRead {return nil,io.EOF}
    p.alreadyRead=true
    b:=buf.New()
    if _,err:=b.Write(p.payload);err!=nil {
        b.Release()
        return nil,err
    }
    return buf.MultiBuffer{b},nil
}
func (p *b05LegacyFlushProbe) LiOnWriteAccepted(n int32)error{
    if !p.writer.finished {return errors.New("ACK before actual lower writer")}
    p.acknowledgements=append(p.acknowledgements,n)
    return nil
}
func (p *b05LegacyFlushProbe) LiOnWriteFailed(error){p.failures++}

type b05LegacyFlushWriter struct {
    finished bool
    written int32
    fail bool
    panicWriter bool
}
func (w *b05LegacyFlushWriter) WriteMultiBuffer(mb buf.MultiBuffer)error{
    n:=mb.Len()
    buf.ReleaseMulti(mb)
    if w.panicWriter {panic("QA only: lower Writer panic")}
    w.finished=true
    if w.fail {return io.ErrShortWrite}
    w.written+=n
    return nil
}

func TestB05LegacyFirstFlushDoesNotConfirmBufferedBytes(t *testing.T){
    writer:=&b05LegacyFlushWriter{}
    input:=&b05LegacyFlushProbe{payload:[]byte("strict-first-client-response"),writer:writer}
    buffered:=buf.NewBufferedWriter(writer)
    if err:=liB05QALegacySSFirstFlush(input,buffered,buffered);err!=nil {
        t.Fatal(err)
    }
    if writer.written!=int32(len(input.payload)) ||
        len(input.acknowledgements)!=1 ||
        input.acknowledgements[0]!=int32(len(input.payload)) ||
        input.failures!=0 {
        t.Fatalf("first-buffer flush proof invalid: written=%d ack=%v failed=%d",
            writer.written,input.acknowledgements,input.failures)
    }
    t.Log("B05_LEGACY_SS_FIRST_FLUSH_FINAL_WRITER_ACK=PASS")
}

func TestB05LegacyFirstFlushErrorNeverAcknowledged(t *testing.T){
    writer:=&b05LegacyFlushWriter{fail:true}
    input:=&b05LegacyFlushProbe{payload:[]byte("must-not-ack"),writer:writer}
    buffered:=buf.NewBufferedWriter(writer)
    err:=liB05QALegacySSFirstFlush(input,buffered,buffered)
    if !errors.Is(err,io.ErrShortWrite) ||
        len(input.acknowledgements)!=0 || input.failures!=1 {
        t.Fatalf("failed final writer falsely ACKed: err=%v ack=%v fail=%d",
            err,input.acknowledgements,input.failures)
    }
    t.Log("B05_LEGACY_SS_FIRST_FLUSH_WRITER_ERROR_FAILCLOSED=PASS")
}

func TestB05LegacyFirstFlushPanicQuarantinesAndRethrows(t *testing.T){
    writer:=&b05LegacyFlushWriter{panicWriter:true}
    input:=&b05LegacyFlushProbe{payload:[]byte("must-quarantine"),writer:writer}
    buffered:=buf.NewBufferedWriter(writer)
    panicked:=false
    func(){
        defer func(){if recover()!=nil{panicked=true}}()
        _=liB05QALegacySSFirstFlush(input,buffered,buffered)
    }()
    if !panicked || len(input.acknowledgements)!=0 || input.failures!=1 {
        t.Fatalf("panic must preserve delivery ambiguity: panic=%v ack=%v failed=%d",
            panicked,input.acknowledgements,input.failures)
    }
    t.Log("B05_LEGACY_SS_FIRST_FLUSH_WRITER_PANIC_RETHROWN=PASS")
}
