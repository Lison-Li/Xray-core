package shadowsocks

import (
 "errors"
 "io"
 "testing"
)

type b05NativeSSOriginalSocket struct {
 accepted int
 fail error
}
func (w *b05NativeSSOriginalSocket) Write(p []byte)(int,error){
 if w.fail!=nil{return 0,w.fail}
 if w.accepted<0{return len(p),nil}
 if w.accepted<len(p){return w.accepted,nil}
 return len(p),nil
}

func TestB05ClassicSSNativeUDPFinalEncryptedSocketWriteAcceptedOnlyAfterFullOriginalPacket(t *testing.T){
 data:=[]byte("real-encrypted-SS-frame-UDP")
 for _,tc:=range []struct{name string;n int;failure error;want error}{
  {"full", -1,nil,nil},
  {"short",8,nil,io.ErrShortWrite},
  {"failed",0,io.ErrClosedPipe,io.ErrClosedPipe},
 }{
  t.Run(tc.name,func(t *testing.T){
   w:=&b05NativeSSOriginalSocket{accepted:tc.n,fail:tc.failure}
   err:=liB05SSNativeFinalEncryptedSocketWrite(w,data)
   if !errors.Is(err,tc.want){
    t.Fatalf("original encrypted UDP socket receipt error=%v expected %v",err,tc.want)
   }
  })
 }
}
