package shadowsocks_2022

import (
    "bytes"
    "context"
    "encoding/base64"
    "errors"
    stdnet "net"
    "testing"

    "github.com/xtls/xray-core/common/protocol"
)

// The real modern MultiUserInbound AddUser/RemoveUser and native
// UDPSessionManager caches are exercised directly. The socket's Write return
// is deliberately fault-injected. This is NOT a real external Mihomo or
// Worker accounting test: it proves the exact in-memory revoke boundary.
func TestB05ModernSS2022ActualCachedNativeUDPRevocationAndReadd(t *testing.T) {
    for _,tc:=range []struct{name,method string;keySize int}{
        {"AES128",MethodAES128GCM,16},
        {"AES256",MethodAES256GCM,32},
    } {
        t.Run(tc.name,func(t *testing.T){
            master:=bytes.Repeat([]byte{0x15},tc.keySize)
            inbound,err:=NewMultiServer(newTestContext(),&MultiUserServerConfig{
                Method:tc.method,
                Key:base64.StdEncoding.EncodeToString(master),
            })
            if err!=nil{t.Fatal(err)}
            oldKey:=bytes.Repeat([]byte{0x41},tc.keySize)
            bKey:=bytes.Repeat([]byte{0x42},tc.keySize)
            old:=&protocol.MemoryUser{Email:"user-a@qa.invalid",Account:&MemoryAccount{Key:oldKey}}
            survivor:=&protocol.MemoryUser{Email:"user-b@qa.invalid",Account:&MemoryAccount{Key:bKey}}
            for _,u:=range []*protocol.MemoryUser{old,survivor}{
                if err:=inbound.AddUser(context.Background(),u);err!=nil{t.Fatal(err)}
            }
            // Different billable UIDs must not share an EIH/PSK hash.
            alias:=&protocol.MemoryUser{Email:"alias-duplicate@qa.invalid",
                Account:&MemoryAccount{Key:append([]byte(nil),oldKey...)}}
            if err:=inbound.AddUser(context.Background(),alias);err==nil {
                t.Fatal("different user using exact duplicate SS2022 EIH key was admitted")
            }
            if inbound.GetUsersCount(context.Background())!=2 {
                t.Fatal("rejected PSK identity modified user count")
            }
            oldHash:=DeriveUserPSKHash(oldKey)
            bHash:=DeriveUserPSKHash(bKey)
            inbound.RLock()
            got,key,ok:=inbound.liB05LiveUDPUser(oldHash,nil)
            inbound.RUnlock()
            if !ok||got!=old||!bytes.Equal(key,oldKey){t.Fatal("original EIH did not authenticate live A")}
            sA:=inbound.udpSessions.GetOrCreate(93021)
            sA.Lock();sA.User=old;sA.UserPSK=oldKey;sA.Unlock()
            sB:=inbound.udpSessions.GetOrCreate(93022)
            sB.Lock();sB.User=survivor;sB.UserPSK=bKey;sB.Unlock()
            wireA,wireAPeer:=stdnet.Pipe();defer wireA.Close();defer wireAPeer.Close()
            wireB,wireBPeer:=stdnet.Pipe();defer wireB.Close();defer wireBPeer.Close()
            packet:=[]byte("original-native-ss2022-encrypted-udp")
            outA:=&b05ShortPacketConn{Conn:wireA,n:len(packet)}
            outB:=&b05ShortPacketConn{Conn:wireB,n:len(packet)}
            sA.currentConn.Store(outA)
            sB.currentConn.Store(outB)
            if err:=sA.WriteToClient(packet);err!=nil{t.Fatal(err)}
            if err:=sB.WriteToClient(packet);err!=nil{t.Fatal(err)}
            if err:=inbound.RemoveUser(context.Background(),old.Email);err!=nil{t.Fatal(err)}
            if !sA.revoked.Load(){t.Fatal("original authenticated A UDP session remained active after RemoveUser")}
            if sB.revoked.Load(){t.Fatal("B unaffected user was incorrectly revoked")}
            if sA.User!=old{t.Fatal("revoked A original session identity unexpectedly lost")}
            if _,ok:=inbound.udpSessions.sessions.Load(93021);ok {
                t.Fatal("revoked A session still reachable from active UDP session manager")
            }
            if active,ok:=inbound.udpSessions.sessions.Load(93022);!ok||active!=sB{
                t.Fatal("survivor B UDP socket/link was wrongly torn down")
            }
            if err:=sA.WriteToClient(packet);!errors.Is(err,ErrInvalidRequest){
                t.Fatalf("revoked A emitted original native encrypted UDP response: %v",err)
            }
            if outA.calls!=1{t.Fatalf("revoked A emitted another encrypted packet: %d calls",outA.calls)}
            if err:=sB.WriteToClient(packet);err!=nil{t.Fatalf("survivor B original native socket lost: %v",err)}
            if outB.calls!=2{t.Fatalf("survivor B lost original socket callback: %d",outB.calls)}
            inbound.RLock()
            _,_,oldOK:=inbound.liB05LiveUDPUser(oldHash,old)
            gotB,keyB,bOK:=inbound.liB05LiveUDPUser(bHash,survivor)
            inbound.RUnlock()
            if oldOK || !bOK || gotB!=survivor || !bytes.Equal(keyB,bKey){
                t.Fatal("deleted old A still authenticates / survivor B denied in live native EIH map")
            }
            // Re-add the SAME email and SAME key. The old session pointer
            // must not inherit new authentication even if EIH hash matches.
            fresh:=&protocol.MemoryUser{Email:old.Email,Account:&MemoryAccount{Key:append([]byte(nil),oldKey...)}}
            if err:=inbound.AddUser(context.Background(),fresh);err!=nil{t.Fatal(err)}
            inbound.RLock()
            _,_,staleOK:=inbound.liB05LiveUDPUser(oldHash,old)
            live,keyFresh,freshOK:=inbound.liB05LiveUDPUser(oldHash,nil)
            inbound.RUnlock()
            if staleOK || !freshOK || live!=fresh || !bytes.Equal(keyFresh,oldKey) {
                t.Fatal("stale removed A UDP session was reused by same-key account re-add")
            }
            if !sA.revoked.Load()||sA.WriteToClient(packet)==nil||outA.calls!=1{
                t.Fatal("old A session resurrected after same-email/same-key re-add")
            }
            replacement:=inbound.udpSessions.GetOrCreate(93021)
            if replacement==sA || replacement.revoked.Load(){
                t.Fatal("new A inherited retired UDP session or revoked state")
            }
            t.Log("B05_MODERN_ORIGINAL_SS2022_NATIVE_UDP_LIVE_EIH_REMOVE_READD_AND_SURVIVOR=PASS_UNIT")
        })
    }
}
