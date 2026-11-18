package mux

import (
    "context"

    "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/session"
)

// An XUDP GlobalID is only eight client-controlled bytes. It is NOT an
// authentication identity. XUDPManager is process-global, so a second client
// deliberately selecting a prior GlobalID must never inherit the first
// client's original outbound UDP socket or the first client's B05 WAL owner.
//
// MemoryUser pointers are stable for a particular authenticated credential in
// the VLESS inbound validator; comparing the pointer prevents a different
// credential with a coincidentally identical configured Email from assuming
// ownership. A user registry refresh allocates a new MemoryUser and
// intentionally refuses reuse of any old egress: fail closed, no migration.
type liB05XUDPOwner struct {
    inboundTag string
    inboundName string
    user *protocol.MemoryUser
    email string
    target string
}

func liB05XUDPOwnerFromContext(ctx context.Context, target net.Destination) (liB05XUDPOwner, bool) {
    in:=session.InboundFromContext(ctx)
    if in==nil || in.User==nil || in.User.Email=="" || in.Tag=="" || in.Name=="" ||
        target.Network!=net.Network_UDP || target.Address==nil || target.Port==0 {
        return liB05XUDPOwner{},false
    }
    // A metadata override sent by the remote client may only affect Source
    // and Local; user, listener Tag, and name come from the authenticated
    // server context. Include the actual destination to block reusing the
    // same GlobalID for an unrelated origin on the same account.
    return liB05XUDPOwner{
        inboundTag:in.Tag,inboundName:in.Name,user:in.User,email:in.User.Email,
        target:target.String(),
    },true
}

func (x *XUDP) liB05SameAuthenticatedOwner(candidate liB05XUDPOwner) bool {
    return x!=nil && x.liB05Owner==candidate &&
        candidate.user!=nil && candidate.inboundTag!="" &&
        candidate.email!="" && candidate.target!=""
}
