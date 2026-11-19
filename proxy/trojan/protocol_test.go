package trojan_test

import (
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/trojan"
)

func toAccount(a *Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func TestTCPRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "love@example.com",
		Account: toAccount(&Account{
			Password: "password",
		}),
	}
	payload := []byte("test string")
	data := buf.New()
	common.Must2(data.Write(payload))

	buffer := buf.New()
	defer buffer.Release()

	destination := net.Destination{Network: net.Network_TCP, Address: net.LocalHostIP, Port: 1234}
	writer := &ConnWriter{Writer: buffer, Target: destination, Account: user.Account.(*MemoryAccount)}
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	reader := &ConnReader{Reader: buffer}
	common.Must(reader.ParseHeader())

	if r := cmp.Diff(reader.Target, destination); r != "" {
		t.Error("destination: ", r)
	}

	decodedData, err := reader.ReadMultiBuffer()
	common.Must(err)
	if r := cmp.Diff(decodedData[0].Bytes(), payload); r != "" {
		t.Error("data: ", r)
	}
}

func TestUDPRequest(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "love@example.com",
		Account: toAccount(&Account{
			Password: "password",
		}),
	}
	payload := []byte("test string")
	data := buf.New()
	common.Must2(data.Write(payload))

	buffer := buf.New()
	defer buffer.Release()

	destination := net.Destination{Network: net.Network_UDP, Address: net.LocalHostIP, Port: 1234}
	writer := &PacketWriter{Writer: &ConnWriter{Writer: buffer, Target: destination, Account: user.Account.(*MemoryAccount)}, Target: destination}
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{data}))

	connReader := &ConnReader{Reader: buffer}
	common.Must(connReader.ParseHeader())

	packetReader := &PacketReader{Reader: connReader}
	mb, err := packetReader.ReadMultiBuffer()
	common.Must(err)

	if mb.IsEmpty() {
		t.Error("no request data")
	}

	mb2, b := buf.SplitFirst(mb)
	defer buf.ReleaseMulti(mb2)

	dest := *b.UDP
	if r := cmp.Diff(dest, destination); r != "" {
		t.Error("destination: ", r)
	}

	if r := cmp.Diff(b.Bytes(), payload); r != "" {
		t.Error("data: ", r)
	}
}


type b05TrojanShortFramedSocketWriter struct{}

func (b05TrojanShortFramedSocketWriter) Write(p []byte) (int,error) {
	if len(p)==0 {return 0,nil}
	return len(p)-1,nil // original lower Writer cannot prove full delivery
}

func TestB05TrojanNativeUDPShortFramedWriteCannotProduceAcceptedReceipt(t *testing.T) {
	writer:=&PacketWriter{
		Writer:b05TrojanShortFramedSocketWriter{},
		Target:net.UDPDestination(net.LocalHostIP,35353),
	}
	original:=buf.FromBytes([]byte("actual-udp-bytes"))
	err:=writer.WriteMultiBuffer(buf.MultiBuffer{original})
	if !errors.Is(err,io.ErrShortWrite) {
		t.Fatalf("partial real framed TLS socket Writer must fail closed, got %v",err)
	}
}
