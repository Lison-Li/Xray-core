package mux

import (
    "testing"
    "time"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/transport/pipe"
)

// This is a structural regression for the exact native Xray MUX Close path.
// The real external B05 metering wrapper implements this *narrow* accessor;
// the MUX must never assume that every Reader is itself *pipe.Reader.
type liB05XUDPVerifiedPipeWrapper struct {
    buf.Reader
    original *pipe.Reader
}

func (w *liB05XUDPVerifiedPipeWrapper) LiB05MuxPipeReader() *pipe.Reader {
    return w.original
}

type liB05XUDPUnknownPipeWrapper struct {
    buf.Reader
}

func liB05XUDPCloseTestSession(t *testing.T, in buf.Reader, out buf.Writer, id byte) (*Session,*XUDP) {
    t.Helper()
    key:=[8]byte{id, 0xB0,0x05,0x11,0x18,0x26,0,1}
    x:=&XUDP{GlobalID:key,Status:Active}
    s:=&Session{input:in,output:out,parent:NewSessionManager(),ID:uint16(id),XUDP:x}
    x.Mux=s
    if !s.parent.Add(s){t.Fatal("actual mux SessionManager rejected newly allocated XUDP")}
    XUDPManager.Lock()
    if XUDPManager.Map[key]!=nil{
        XUDPManager.Unlock()
        t.Fatal("test-only XUDP ID unexpectedly occupied")
    }
    XUDPManager.Map[key]=x
    XUDPManager.Unlock()
    t.Cleanup(func(){
        XUDPManager.Lock()
        if XUDPManager.Map[key]==x {delete(XUDPManager.Map,key)}
        XUDPManager.Unlock()
    })
    return s,x
}

func TestLiB05RealMuxXUDPWrappedVerifiedPipeReaderCloseKeepsReconnectState(t *testing.T){
    raw, writer:=pipe.New()
    // This matches real B05 final Writer metering: wrapper.Reader delegates
    // original raw transport pipe while owning the post-Writer WAL intent.
    wrapper:=&liB05XUDPVerifiedPipeWrapper{Reader:raw,original:raw}
    session,x:=liB05XUDPCloseTestSession(t,wrapper,writer,231)
    if err:=session.Close(false);err!=nil{t.Fatal(err)}
    if !session.closed || x.Status!=Expiring {
        t.Fatal("actual XUDP wrapped Close failed to enter reconnect grace state")
    }
    if x.Expire.Before(time.Now().Add(50*time.Second)){
        t.Fatal("valid verified pipe lost 1-minute reconnect grace period")
    }
    XUDPManager.Lock()
    retained:=XUDPManager.Map[x.GlobalID]==x
    XUDPManager.Unlock()
    if !retained {t.Fatal("wrapped genuine pipe reader lost recoverable XUDP identity")}
    if residue:=raw.Recover();residue!=nil{
        t.Fatalf("wrapped XUDP Close failed to recover injected EOF: %v",residue)
    }
    t.Log("B05_XUDP_ACTUAL_MUX_WRAPPED_ORIGINAL_PIPE_CLOSE_NO_PANIC_REUSE_STATE=PASS")
}

func TestLiB05RealMuxXUDPOriginalPipeReaderCloseUnchanged(t *testing.T){
    raw,writer:=pipe.New()
    session,x:=liB05XUDPCloseTestSession(t,raw,writer,232)
    if err:=session.Close(false);err!=nil{t.Fatal(err)}
    if x.Status!=Expiring{t.Fatal("legacy original pipe XUDP graceful Close regressed")}
    if residue:=raw.Recover();residue!=nil{t.Fatalf("original pipe leftover EOF: %v",residue)}
    t.Log("B05_XUDP_ORIGINAL_UNWRAPPED_PIPE_BEHAVIOR_UNCHANGED=PASS")
}

func TestLiB05RealMuxXUDPUnknownReaderFailsClosedWithoutPanic(t *testing.T){
    raw,writer:=pipe.New()
    // An arbitrary reader wrapper must NOT bypass the underlying-pipe
    // capability check. It cannot be treated as a reconnectable XUDP.
    unknown:=&liB05XUDPUnknownPipeWrapper{Reader:raw}
    session,x:=liB05XUDPCloseTestSession(t,unknown,writer,233)
    if err:=session.Close(false);err!=nil{t.Fatal(err)}
    XUDPManager.Lock()
    _,present:=XUDPManager.Map[x.GlobalID]
    XUDPManager.Unlock()
    if present{t.Fatal("unverified XUDP Reader retained global ID after close")}
    if x.Status!=Expiring || x.Expire.After(time.Now().Add(time.Second)){
        t.Fatal("unverified XUDP Reader wrongly entered reconnect grace")
    }
    t.Log("B05_XUDP_UNVERIFIED_READER_NO_PANIC_NO_GLOBAL_ID_REUSE=PASS")
}
