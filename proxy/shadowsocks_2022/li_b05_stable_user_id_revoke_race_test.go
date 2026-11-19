package shadowsocks_2022

import (
    "context"
    "encoding/base64"
    "fmt"
    "sync"
    "testing"

    "github.com/xtls/xray-core/common/protocol"
)

func b05SS2022StableUser(t *testing.T,label string,keyByte byte)*protocol.MemoryUser {
    t.Helper()
    key:=make([]byte,16)
    for i:=range key {key[i]=keyByte}
    return &protocol.MemoryUser{
        Email:label+"@b05.qa.invalid",
        Account:&MemoryAccount{Key:base64.StdEncoding.EncodeToString(key)},
    }
}
func b05SS2022StableMulti(t *testing.T)*MultiUserInbound{
    t.Helper()
    key:=make([]byte,16)
    for i:=range key {key[i]=0xc3}
    i,err:=NewMultiServer(context.Background(),&MultiUserServerConfig{
        Method:"2022-blake3-aes-128-gcm",Key:base64.StdEncoding.EncodeToString(key),
    })
    if err!=nil {t.Fatalf("actual sing-shadowsocks MultiService initialization: %v",err)}
    return i
}
func TestB05SS2022RemoveUserPreservesStableAuthenticatedIDAndRejectsReusedOldContext(t *testing.T){
    i:=b05SS2022StableMulti(t)
    ctx:=context.Background()
    for k,label:=range []string{"alpha","bravo","charlie"} {
        if err:=i.AddUser(ctx,b05SS2022StableUser(t,label,byte(k+1)));err!=nil {t.Fatal(err)}
    }
    // Original IDs 0,1,2 correspond to old authenticated packets, not
    // the users' mutable presentation positions after revocation.
    if err:=i.RemoveUser(ctx,"alpha@b05.qa.invalid");err!=nil {t.Fatal(err)}
    if _,err:=i.liB05AuthenticatedUserByID(0);err==nil {
        t.Fatal("deleted original user ID 0 still authenticated")
    }
    for _,tc:=range []struct{id int;email string}{{1,"bravo@b05.qa.invalid"},{2,"charlie@b05.qa.invalid"}}{
        got,err:=i.liB05AuthenticatedUserByID(tc.id)
        if err!=nil || got.Email!=tc.email {t.Fatalf("index %d alias after delete: %v, %v",tc.id,got,err)}
    }
    if err:=i.AddUser(ctx,b05SS2022StableUser(t,"delta",4));err!=nil {t.Fatal(err)}
    if _,err:=i.liB05AuthenticatedUserByID(0);err==nil {
        t.Fatal("deleted user ID 0 rebound to newly added user")
    }
    got,err:=i.liB05AuthenticatedUserByID(3)
    if err!=nil || got.Email!="delta@b05.qa.invalid" {t.Fatalf("new user not monotonic ID 3: %v %v",got,err)}
    if err:=i.RemoveUser(ctx,"bravo@b05.qa.invalid");err!=nil {t.Fatal(err)}
    if _,err:=i.liB05AuthenticatedUserByID(1);err==nil {t.Fatal("deleted ID 1 reused")}
    got,err=i.liB05AuthenticatedUserByID(2)
    if err!=nil || got.Email!="charlie@b05.qa.invalid" {t.Fatalf("survivor ID 2 rebinding: %v %v",got,err)}
    got,err=i.liB05AuthenticatedUserByID(3)
    if err!=nil || got.Email!="delta@b05.qa.invalid" {t.Fatalf("survivor ID 3 rebinding: %v %v",got,err)}
    if i.GetUsersCount(ctx)!=2 || len(i.GetUsers(ctx))!=2 {
        t.Fatal("user management snapshot not synchronized with stable service IDs")
    }
    if err:=i.AddUser(ctx,b05SS2022StableUser(t,"delta",5));err==nil {
        t.Fatal("case-insensitive duplicate authenticated identity admitted")
    }
    if _,err:=i.liB05AuthenticatedUserByID(100000);err==nil {t.Fatal("unknown identity admitted")}
    t.Log("B05_SS2022_REVOKE_READD_ORIGINAL_STABLE_UID_NO_ALIAS=PASS_ACTUAL_SING_SERVICE")
}

func TestB05SS2022AuthenticatedUserReadConcurrentRevokeAndReadd(t *testing.T){
    i:=b05SS2022StableMulti(t)
    ctx:=context.Background()
    for k,label:=range []string{"alpha","bravo","charlie"} {
        if err:=i.AddUser(ctx,b05SS2022StableUser(t,label,byte(k+1)));err!=nil {t.Fatal(err)}
    }
    var wg sync.WaitGroup
    errCh:=make(chan error,8)
    for worker:=0;worker<4;worker++ {
        wg.Add(1)
        go func(){
            defer wg.Done()
            for j:=0;j<70;j++{
                user,err:=i.liB05AuthenticatedUserByID(2)
                if err!=nil || user.Email!="charlie@b05.qa.invalid" {
                    errCh<-fmt.Errorf("surviving ID 2 changed: %v %v",user,err)
                    return
                }
                i.GetUsers(ctx)
                i.GetUsersCount(ctx)
            }
        }()
    }
    wg.Add(1)
    go func(){
        defer wg.Done()
        if err:=i.RemoveUser(ctx,"alpha@b05.qa.invalid");err!=nil {errCh<-err;return}
        for j:=0;j<18;j++ {
            label:=fmt.Sprintf("temp%d",j)
            user:=&protocol.MemoryUser{
                Email:label+"@b05.qa.invalid",
                Account:&MemoryAccount{Key:base64.StdEncoding.EncodeToString([]byte{
                    byte(j+1),byte(j+2),byte(j+3),byte(j+4),
                    byte(j+5),byte(j+6),byte(j+7),byte(j+8),
                    byte(j+9),byte(j+10),byte(j+11),byte(j+12),
                    byte(j+13),byte(j+14),byte(j+15),byte(j+16),
                })},
            }
            if err:=i.AddUser(ctx,user);err!=nil {errCh<-err;return}
            if err:=i.RemoveUser(ctx,user.Email);err!=nil {errCh<-err;return}
        }
    }()
    wg.Wait()
    close(errCh)
    for err:=range errCh {t.Error(err)}
    if _,err:=i.liB05AuthenticatedUserByID(0);err==nil {t.Fatal("removed original user ID reused under concurrent updates")}
    got,err:=i.liB05AuthenticatedUserByID(2)
    if err!=nil || got.Email!="charlie@b05.qa.invalid" {t.Fatalf("identity aliased after concurrent churn: %v %v",got,err)}
    t.Log("B05_SS2022_MULTISERVICE_ORIGINAL_UID_CONCURRENT_REVOKE_READ=PASS_GO_INPROCESS")
}
