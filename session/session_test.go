package session

import (
	"net/http"
	"testing"
	"time"

	"sslcon/proto"
)

func TestNewConnSessionParsing(t *testing.T) {
	h := http.Header{}
	h.Set("X-CSTP-Address", "10.0.0.1")
	h.Set("X-CSTP-Netmask", "255.255.224.0")
	h.Set("X-CSTP-MTU", "1255")
	h.Set("X-CSTP-DNS", "223.5.5.5")
	h.Set("X-CSTP-Content-Encoding", "oc-lz4")
	h.Set("X-DTLS-Content-Encoding", "lzs")
	h.Set("X-CSTP-Idle-Timeout", "1800")
	h.Set("X-CSTP-Lease-Duration", "1209600")
	h.Set("X-CSTP-Session-Timeout", "none") // ASA 可能下发 "none"
	h.Set("X-CSTP-Session-Timeout-Remaining", "3600")
	h.Set("X-DTLS-Port", "1443")
	h.Set("X-DTLS-Session-ID", "295961B188F2220F879A93B7979E3E86A4201E5F4425F842D67A0F50608E4343")

	cSess := Sess.NewConnSession(&h)

	if cSess.VPNAddress != "10.0.0.1" {
		t.Errorf("VPNAddress = %q", cSess.VPNAddress)
	}
	if cSess.MTU != 1255 {
		t.Errorf("MTU = %d", cSess.MTU)
	}
	if cSess.CSTPCompression != proto.CompLZ4 {
		t.Errorf("CSTPCompression = %v, want oc-lz4", cSess.CSTPCompression)
	}
	if cSess.DTLSCompression != proto.CompLZS {
		t.Errorf("DTLSCompression = %v, want lzs", cSess.DTLSCompression)
	}
	// 协商了压缩时应创建统计结构
	if cSess.CompressStat == nil {
		t.Error("CompressStat 应为非 nil")
	}
	if cSess.IdleTimeout != 1800 {
		t.Errorf("IdleTimeout = %d", cSess.IdleTimeout)
	}
	// Lease-Duration(1209600) 与 Session-Timeout-Remaining(3600) 取最小值
	want := time.Now().Add(3600 * time.Second)
	if cSess.AuthExpiration.IsZero() {
		t.Fatal("AuthExpiration 未设置")
	}
	if diff := cSess.AuthExpiration.Sub(want); diff > 5*time.Second || diff < -5*time.Second {
		t.Errorf("AuthExpiration = %v, want ~%v", cSess.AuthExpiration, want)
	}
	if cSess.DTLSPort != "1443" {
		t.Errorf("DTLSPort = %q", cSess.DTLSPort)
	}
}

// 无超时头时不应设置 AuthExpiration（ocserv 不发送时行为不变）
func TestNewConnSessionNoTimeout(t *testing.T) {
	h := http.Header{}
	h.Set("X-CSTP-Address", "10.0.0.1")
	cSess := Sess.NewConnSession(&h)
	if !cSess.AuthExpiration.IsZero() {
		t.Errorf("AuthExpiration 应为零值，got %v", cSess.AuthExpiration)
	}
	if cSess.CSTPCompression != proto.CompNone {
		t.Errorf("CSTPCompression 应为 none，got %v", cSess.CSTPCompression)
	}
	if cSess.CompressStat != nil {
		t.Error("未协商压缩时 CompressStat 应为 nil")
	}
}
