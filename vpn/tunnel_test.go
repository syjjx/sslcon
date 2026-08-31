package vpn

import (
	"testing"

	"sslcon/base"
)

// TestCompressionHeadersToggle 回归：关闭压缩后必须清除上一次开启时写入的
// X-*-Accept-Encoding 头。reqHeaders 是进程级 map（vpnagent 常驻跨连接复用），
// 修复前只写不删，导致关闭压缩重连时仍向服务端广告压缩、协商结果始终为开启。
func TestCompressionHeadersToggle(t *testing.T) {
	// 开启 → 广告压缩能力
	base.Cfg.Compression = true
	applyCompressionHeaders()
	if got := reqHeaders["X-CSTP-Accept-Encoding"]; got != "oc-lz4,lzs" {
		t.Errorf("开启压缩时 X-CSTP-Accept-Encoding = %q, want oc-lz4,lzs", got)
	}
	if got := reqHeaders["X-DTLS-Accept-Encoding"]; got != "oc-lz4,lzs" {
		t.Errorf("开启压缩时 X-DTLS-Accept-Encoding = %q, want oc-lz4,lzs", got)
	}

	// 关闭 → 必须移除残留头（修复前此处失败：键仍存在，重连后协商仍开启）
	base.Cfg.Compression = false
	applyCompressionHeaders()
	if _, ok := reqHeaders["X-CSTP-Accept-Encoding"]; ok {
		t.Error("关闭压缩后 X-CSTP-Accept-Encoding 仍残留，会导致服务端继续协商压缩")
	}
	if _, ok := reqHeaders["X-DTLS-Accept-Encoding"]; ok {
		t.Error("关闭压缩后 X-DTLS-Accept-Encoding 仍残留，会导致服务端继续协商压缩")
	}

	// 再次开启 → 恢复广告
	base.Cfg.Compression = true
	applyCompressionHeaders()
	if got := reqHeaders["X-CSTP-Accept-Encoding"]; got != "oc-lz4,lzs" {
		t.Errorf("再次开启压缩后 X-CSTP-Accept-Encoding = %q, want oc-lz4,lzs", got)
	}
	if got := reqHeaders["X-DTLS-Accept-Encoding"]; got != "oc-lz4,lzs" {
		t.Errorf("再次开启压缩后 X-DTLS-Accept-Encoding = %q, want oc-lz4,lzs", got)
	}
}
