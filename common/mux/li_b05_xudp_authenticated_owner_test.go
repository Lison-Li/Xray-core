package mux

import (
    "bytes"
    "context"
    "strings"
    "testing"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/session"
)

func liB05XUDPTestContext(tag string, user *protocol.MemoryUser) context.Context {
    return session.ContextWithInbound(context.Background(),&session.Inbound{
        Tag:tag,Name:"vless",User:user,
    })
}

func TestLiB05XUDPGlobalIDCannotGrantOtherCredentialOrNodeOrTarget(t *testing.T) {
    original:=&protocol.MemoryUser{Email:"same-email@configured.invalid"}
    otherCredential:=&protocol.MemoryUser{Email:original.Email}
    d1:=net.UDPDestination(net.ParseAddress("127.0.0.1"),5353)
    d2:=net.UDPDestination(net.ParseAddress("127.0.0.1"),5354)
    first,ok:=liB05XUDPOwnerFromContext(liB05XUDPTestContext("Vless_node_1",original),d1)
    if !ok{t.Fatal("real authenticated user not admitted into safe XUDP owner scope")}
    cached:=&XUDP{liB05Owner:first}
    for name,ctxDest:=range map[string]struct{ctx context.Context;target net.Destination}{
        "different credential with SAME configured email":{liB05XUDPTestContext("Vless_node_1",otherCredential),d1},
        "other node using SAME credential":{liB05XUDPTestContext("Vless_node_2",original),d1},
        "same user but DIFFERENT UDP target":{liB05XUDPTestContext("Vless_node_1",original),d2},
    }{
        scope,valid:=liB05XUDPOwnerFromContext(ctxDest.ctx,ctxDest.target)
        if !valid {t.Fatalf("%s scope unexpectedly invalid; test could pass for wrong reason",name)}
        if cached.liB05SameAuthenticatedOwner(scope){
            t.Fatalf("CLIENT_CONTROLLED_XUDP_GLOBAL_ID_CROSS_OWNER_EGRESS_LEAK: %s",name)
        }
    }
    second,ok:=liB05XUDPOwnerFromContext(liB05XUDPTestContext("Vless_node_1",original),d1)
    if !ok||!cached.liB05SameAuthenticatedOwner(second){
        t.Fatal("same authenticated credential/node/UDP target cannot reconnect to its own cached session")
    }
    for _,tc:=range []struct{name string;ctx context.Context;dest net.Destination}{
        {"missing authenticated user",liB05XUDPTestContext("Vless_node_1",nil),d1},
        {"missing node tag",liB05XUDPTestContext("",original),d1},
        {"missing client email",liB05XUDPTestContext("Vless_node_1",&protocol.MemoryUser{}),d1},
        {"non-UDP destination",liB05XUDPTestContext("Vless_node_1",original),net.TCPDestination(net.ParseAddress("127.0.0.1"),5353)},
    }{
        if _,ok:=liB05XUDPOwnerFromContext(tc.ctx,tc.dest);ok{
            t.Fatalf("anonymous or invalid client acquired authenticated XUDP owner: %s",tc.name)
        }
    }
    t.Log("B05_REAL_NATIVE_XUDP_GLOBALID_PER_CREDENTIAL_NODE_TARGET_BINDING=PASS")
}

func TestLiB05XUDPRealMuxStatusNewRejectsForeignGlobalIDBeforeOriginalEgress(t *testing.T){
    // Real core handleStatusNew, real serialized MUX packet, real
    // SessionManager/global ID cache. No simulated Authorize-only call:
    // incorrect code would try to reuse the owner's nil old Mux and panic.
    original:=&protocol.MemoryUser{Email:"same-email@configured.invalid"}
    foreign:=&protocol.MemoryUser{Email:original.Email}
    destination:=net.UDPDestination(net.ParseAddress("127.0.0.1"),15553)
    scope,ok:=liB05XUDPOwnerFromContext(liB05XUDPTestContext("Vless_node_1",original),destination)
    if !ok{t.Fatal("valid original authenticated owner missing")}
    globalID:=[8]byte{0xba,0x05,0x11,0x18,0x26,0,0x44,0x66}
    x:=&XUDP{GlobalID:globalID,Status:Expiring,liB05Owner:scope}
    XUDPManager.Lock()
    if XUDPManager.Map[globalID]!=nil{
        XUDPManager.Unlock()
        t.Fatal("XUDP global ID collision in test fixture")
    }
    XUDPManager.Map[globalID]=x
    XUDPManager.Unlock()
    t.Cleanup(func(){
        XUDPManager.Lock()
        if XUDPManager.Map[globalID]==x {delete(XUDPManager.Map,globalID)}
        XUDPManager.Unlock()
    })
    for _,tc:=range []struct{name string;ctx context.Context;dest net.Destination}{
        {"same email different authenticated user",liB05XUDPTestContext("Vless_node_1",foreign),destination},
        {"same authenticated user different node",liB05XUDPTestContext("Vless_node_2",original),destination},
        {"same authenticated user different destination",liB05XUDPTestContext("Vless_node_1",original),net.UDPDestination(net.ParseAddress("127.0.0.1"),15554)},
    }{
        t.Run(tc.name,func(t *testing.T){
            // Exactly one serialized PacketReader payload; the core must
            // reject the bad owner after parsing, before dispatch/reuse.
            payload:=[]byte("real-native-mux-child-packet")
            raw:=append([]byte{0,byte(len(payload))},payload...)
            rdr:=&buf.BufferedReader{Reader:buf.NewReader(bytes.NewReader(raw))}
            worker:=&ServerWorker{sessionManager:NewSessionManager()}
            meta:=&FrameMetadata{GlobalID:globalID,Target:tc.dest,SessionID:33}
            err:=worker.handleStatusNew(tc.ctx,meta,rdr)
            if err==nil||!strings.Contains(err.Error(),"XUDP authenticated node/user/destination mismatch"){
                t.Fatalf("foreign XUDP GlobalID was not stopped by native handleStatusNew: %v",err)
            }
            XUDPManager.Lock()
            same:=XUDPManager.Map[globalID]==x
            status:=x.Status
            XUDPManager.Unlock()
            if !same||status!=Expiring{
                t.Fatal("foreign MUX attempt modified original user's cached outbound or status")
            }
        })
    }
    t.Log("B05_XUDP_REAL_MUX_FORGED_GLOBALID_DENIED_BEFORE_ORIGINAL_OUTBOUND=PASS")
}
