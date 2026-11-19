package udp_test

// The real Trojan UDP implementation writes downlink datagrams through a
// direct Dispatcher callback and the original framed socket PacketWriter,
// NOT through buf.Copy. A staged strict Reader must receive its original
// post-write receipt only AFTER that callback returns nil. This small
// source regression does not replace the genuine overseas Mihomo/XrayR/TLS
// socket and CRC WAL acceptance.
import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
)

type b05OriginalReceiptSource struct {
	mu sync.Mutex
	sent bool
	events chan string
}

func (s *b05OriginalReceiptSource) ReadMultiBuffer() (buf.MultiBuffer,error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent {return nil,io.EOF}
	s.sent=true
	return buf.MultiBuffer{buf.FromBytes([]byte("trojan-a")),buf.FromBytes([]byte("trojan-b"))},nil
}

func (s *b05OriginalReceiptSource) LiOnWriteAccepted(n int32) error {
	s.events <- "confirm:"+stringifyB05ReceiptSize(n)
	return nil
}

func stringifyB05ReceiptSize(n int32) string {
	if n!=16 {return "unexpected"}
	return "16"
}

func (s *b05OriginalReceiptSource) LiOnWriteFailed(err error) {
	if err!=nil {s.events <- "failed"}
}

func receiveOriginalWriterEvent(t *testing.T,ch <-chan string) string {
	t.Helper()
	select {
	case value:=<-ch:return value
	case <-time.After(3*time.Second):t.Fatal("real Dispatcher callback/receipt event timed out");return ""
	}
}

func TestB05TrojanUDPReceiptOnlyAfterCallbackReturnsFromFinalSocketWriter(t *testing.T) {
	for _,tt:=range []struct{name string;failSecond bool;want string}{
		{"all-two-framed-datagrams-succeeded",false,"confirm:16"},
		{"second-framed-datagram-socket-error",true,"failed"},
	}{
		t.Run(tt.name,func(t *testing.T){
			source:=&b05OriginalReceiptSource{events:make(chan string,6)}
			firstReturned:=make(chan struct{},1)
			releaseFirst:=make(chan struct{})
			defer close(releaseFirst)
			target:=net.UDPDestination(net.LocalHostIP,53053)
			mockDispatcher:=&TestDispatcher{
				OnDispatch:func(ctx context.Context,dst net.Destination)(*transport.Link,error){
					return &transport.Link{Reader:source,Writer:buf.Discard},nil
				},
			}
			ctx,cancel:=context.WithCancel(context.Background())
			defer cancel()
			var callbackNumber int
			response:=NewDispatcherWithFinalWriterReceipt(mockDispatcher,
				func(_ context.Context, packet *udp_proto.Packet)error{
					callbackNumber++
					packet.Payload.Release()
					if callbackNumber==1 {
						firstReturned<-struct{}{}
						<-releaseFirst
					}
					if tt.failSecond && callbackNumber==2 {
						return errors.New("physical Trojan UDP socket failed after one prior accepted datagram")
					}
					return nil
				})
			original:=buf.FromBytes([]byte("request"))
			response.Dispatch(ctx,target,original)
			select {
			case <-firstReturned:
			case <-time.After(3*time.Second):t.Fatal("original UDP response callback never reached")
			}
			select {
			case early:=<-source.events:
				t.Fatalf("premature WAL receipt before underlying Writer returned: %q",early)
			default:
			}
			releaseFirst<-struct{}{}
			if got:=receiveOriginalWriterEvent(t,source.events);got!=tt.want {
				t.Fatalf("invalid confirmed original Writer result %q, want %q",got,tt.want)
			}
			select {
			case duplicate:=<-source.events:
				t.Fatalf("receipt applied twice or ambiguous downlink credited: %q",duplicate)
			default:
			}
			if callbackNumber!=2 {t.Fatalf("expected both actual framed packet writes, got %d",callbackNumber)}
			response.RemoveRay()
		})
	}
}
