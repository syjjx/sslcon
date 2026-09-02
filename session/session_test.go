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

// 自动重连时旧会话的清理可能延迟执行（如 TLS 读卡在半个 TCP 连接上，网络恢复后
// 才报错）。旧会话 Close() 绝不能误伤已替换的新会话：不得置空全局 Sess.CSess、
// 不得关闭新会话的 Sess.CloseChan。这是 DTLS 重连竞态（误 ABORT、孤儿会话）的
// 回归测试。
func TestConnSessionCloseDoesNotTouchNewSession(t *testing.T) {
	h := http.Header{}
	h.Set("X-CSTP-Address", "10.0.0.1")

	// 模拟旧会话（自动重连前的会话）
	oldSess := Sess.NewConnSession(&h)

	// 模拟新会话：自动重连成功后替换全局 Sess.CSess / Sess.CloseChan
	newSess := Sess.NewConnSession(&h)
	if Sess.CSess != newSess {
		t.Fatal("Sess.CSess 应指向新会话")
	}

	// 旧会话的延迟清理：不得触碰新会话的全局状态
	oldSess.Close()
	if Sess.CSess != newSess {
		t.Error("旧会话 Close() 误将 Sess.CSess 置空")
	}
	select {
	case <-Sess.CloseChan:
		t.Error("旧会话 Close() 误关闭了新会话的 Sess.CloseChan")
	default:
	}
	// 旧会话自己的 CloseChan 应已关闭（ReadDeadTimer 依赖它退出）
	select {
	case <-oldSess.CloseChan:
	default:
		t.Error("旧会话自己的 CloseChan 应已关闭")
	}

	// 新会话关闭时仍能正常清理全局
	newSess.Close()
	if Sess.CSess != nil {
		t.Error("新会话 Close() 后 Sess.CSess 应为 nil")
	}
	select {
	case <-Sess.CloseChan:
	default:
		t.Error("新会话 Close() 后 Sess.CloseChan 应已关闭")
	}
}

// 与上同理：旧会话 DtlsSession 的关闭不得清除新会话的 DTLS 协商状态。
func TestDtlsSessionCloseDoesNotTouchNewSession(t *testing.T) {
	h := http.Header{}
	h.Set("X-CSTP-Address", "10.0.0.1")

	oldSess := Sess.NewConnSession(&h)
	newSess := Sess.NewConnSession(&h)

	oldSess.DtlsConnected.Store(true)
	newSess.DtlsConnected.Store(true)
	newSess.DTLSCipherSuite = "ECDHE-ECDSA-AES128-GCM-SHA256"

	// 旧会话的 DSess 关闭：只应关闭自己的 CloseChan，不得清新会话状态
	oldSess.DSess.Close()
	if !newSess.DtlsConnected.Load() {
		t.Error("旧会话 DSess.Close() 误清了新会话的 DtlsConnected")
	}
	if newSess.DTLSCipherSuite == "" {
		t.Error("旧会话 DSess.Close() 误清了新会话的 DTLSCipherSuite")
	}

	// 新会话自己的 DSess 关闭：正常清除自己的状态
	newSess.DSess.Close()
	if newSess.DtlsConnected.Load() {
		t.Error("新会话 DSess.Close() 后 DtlsConnected 应为 false")
	}
	if newSess.DTLSCipherSuite != "" {
		t.Error("新会话 DSess.Close() 后 DTLSCipherSuite 应为空")
	}
}
