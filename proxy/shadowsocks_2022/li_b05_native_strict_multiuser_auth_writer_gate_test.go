package shadowsocks_2022

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestB05NativeTCPStrictReceiptRequiresActualAuthenticatedMultiUserBinding(t *testing.T) {
	method, err := GetCipherMethod(MethodAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	w := NewServerStreamWriter(&bytes.Buffer{}, method, bytes.Repeat([]byte{0x5b}, 16), bytes.Repeat([]byte{0x47}, 16))
	if _, ok := liB05BoundNativeOriginalTCPWriter(w); ok {
		t.Fatal("single-user original encrypted TCP writer accepted without an authenticated/revoke-bound multiuser identity")
	}
	if _, ok := liB05BoundNativeOriginalTCPWriter(buf.Discard); ok {
		t.Fatal("unrelated internal pipe writer accepted as original SS2022 encrypted socket")
	}
	binding := &liB05TCPBinding{}
	w.liB05NativeTCPBinding = binding
	if physical, ok := liB05BoundNativeOriginalTCPWriter(w); !ok || physical != w {
		t.Fatal("authenticated multiuser-bound TCP writer was rejected")
	}
	binding.liB05Revoked.Store(true)
	if _, ok := liB05BoundNativeOriginalTCPWriter(w); ok {
		t.Fatal("revoked original TCP binding was permitted after user deletion")
	}
}
