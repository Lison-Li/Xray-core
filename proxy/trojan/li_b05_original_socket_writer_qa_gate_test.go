package trojan

// QA-only pre-listener gate unit test: not real UDP acceptance.
// Real Mihomo encrypted TCP+UDP and CRC/fsync original socket WAL remains
// required independently before any release.
import (
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestB05TrojanOriginalSocketWriterGateDefaultDenialAndExactLoopback(t *testing.T) {
	const tag = "Trojan_127.0.0.1_56957"
	in := &session.Inbound{Name: "trojan", Tag: tag}
	flags := []string{
		"QA_ALL13_REAL_NATIVE_STRICT_WAL",
		"XRAYR_LI_B05_STRICT",
		"XRAYR_LI_B05_PUBLIC_MULTI_NODE",
		"XRAYR_LI_B05_PUBLIC_MULTI_WRITER_ACK",
		"XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_QA",
		"XRAYR_LI_B05_PUBLIC_MULTI_13_NATIVE_WRITER_ACK",
		"XRAYR_LI_B05_ALL13_UDP_TUNNEL_LOOPBACK_QA",
		"XRAYR_LI_B05_ALL13_UDP_TUNNEL_WRITER_ACK",
	}
	for _, flag := range flags {
		t.Setenv(flag, "0")
	}
	if liB05TrojanOriginalSocketWriterQA(in) { t.Fatal("strict QA enabled without flags") }
	for _, flag := range flags {
		t.Setenv(flag, "1")
	}
	if !liB05TrojanOriginalSocketWriterQA(in) { t.Fatal("all explicitly linked QA gates denied") }
	for _, flag := range flags {
		t.Setenv(flag, "0")
		if liB05TrojanOriginalSocketWriterQA(in) {
			t.Fatalf("half-armed original socket Writer QA accepted missing %s", flag)
		}
		t.Setenv(flag, "1")
	}
	for _, other := range []*session.Inbound{
		nil,
		{Name: "vmess", Tag: tag},
		{Name: "trojan", Tag: "Trojan_192.0.2.1_56957"},
		{Name: "trojan", Tag: "Vless_127.0.0.1_56957"},
	} {
		if liB05TrojanOriginalSocketWriterQA(other) {
			t.Fatalf("unrelated or public inbound unexpectedly authorized: %#v", other)
		}
	}
}
