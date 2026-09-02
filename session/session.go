package session

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"
	"sslcon/base"
	"sslcon/proto"
	"sslcon/utils"
)

var (
	Sess = &Session{}
)

type Session struct {
	SessionToken    string
	PreMasterSecret []byte

	ActiveClose bool
	CloseChan   chan struct{} // 用于通知所有 UI，ConnSession 已关闭
	CSess       *ConnSession
}

type stat struct {
	// be sure to use the double type when parsing
	BytesSent     uint64 `json:"bytesSent"`
	BytesReceived uint64 `json:"bytesReceived"`
}

// CompressStat 压缩统计（仅在协商压缩时累计，原子计数）。
// 压缩率 = 1 - wire/original；original 为压缩前的原始载荷字节，wire 为压缩后实际线上字节。
type CompressStat struct {
	SendOriginal int64 `json:"send_original"` // 发送方向：压缩前载荷字节数
	SendWire     int64 `json:"send_wire"`     // 发送方向：压缩后线上载荷字节数
	RecvWire     int64 `json:"recv_wire"`     // 接收方向：线上收到的压缩载荷字节数
	RecvOriginal int64 `json:"recv_original"` // 接收方向：解压后的载荷字节数
}

// ConnSession used for both TLS and DTLS
type ConnSession struct {
	Sess *Session `json:"-"`

	ServerAddress string
	LocalAddress  string
	Hostname      string
	TunName       string
	VPNAddress    string // The IPv4 address of the client
	VPNMask       string // IPv4 netmask
	DNS           []string
	MTU           int
	SplitInclude  []string
	SplitExclude  []string

	DynamicSplitTunneling       bool
	DynamicSplitIncludeDomains  []string
	DynamicSplitIncludeResolved SyncMap // https://github.com/golang/go/issues/31136
	DynamicSplitExcludeDomains  []string
	DynamicSplitExcludeResolved SyncMap

	TLSCipherSuite    string
	TLSDpdTime        int // https://datatracker.ietf.org/doc/html/rfc3706
	TLSKeepaliveTime  int
	DTLSPort          string
	DTLSDpdTime       int
	DTLSKeepaliveTime int
	DTLSId            string `json:"-"` // used by the server to associate the DTLS channel with the CSTP channel
	DTLSCipherSuite   string

	// 压缩协商（X-CSTP-Content-Encoding / X-DTLS-Content-Encoding）
	CSTPCompression proto.Compression `json:"cstp_compression"`
	DTLSCompression proto.Compression `json:"dtls_compression"`

	// 会话超时/租期（X-CSTP-Idle-Timeout / Lease-Duration / Session-Timeout）
	IdleTimeout    int       `json:"idle_timeout"`
	AuthExpiration time.Time `json:"auth_expiration"` // 会话到期时间（三者最小值+连接时刻）

	Stat         *stat
	CompressStat *CompressStat `json:"compress_stat"` // 压缩统计，未协商压缩时为 null

	closeOnce      sync.Once           `json:"-"`
	CloseChan      chan struct{}       `json:"-"`
	PayloadIn      chan *proto.Payload `json:"-"`
	PayloadOutTLS  chan *proto.Payload `json:"-"`
	PayloadOutDTLS chan *proto.Payload `json:"-"`

	DtlsConnected *atomic.Bool
	DtlsSetupChan chan struct{} `json:"-"`
	DSess         *DtlsSession  `json:"-"`

	ResetTLSReadDead  *atomic.Bool `json:"-"`
	ResetDTLSReadDead *atomic.Bool `json:"-"`
}

type DtlsSession struct {
	closeOnce sync.Once
	CloseChan chan struct{}
}

// SyncMap 包装 sync.Map 并提供 JSON 序列化能力：
// sync.Map 没有导出字段，json.Marshal 只会输出 {}，导致 status 看不到已解析的域名映射
type SyncMap struct {
	sync.Map
}

func (m *SyncMap) MarshalJSON() ([]byte, error) {
	out := make(map[string][]string)
	m.Range(func(k, v interface{}) bool {
		if ips, ok := v.([]string); ok {
			out[fmt.Sprint(k)] = ips
		}
		return true
	})
	return json.Marshal(out)
}

// atoiSafe 忽略解析错误，服务器可能下发 "none" 等非数值
func atoiSafe(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func (sess *Session) NewConnSession(header *http.Header) *ConnSession {
	cSess := &ConnSession{
		Sess:              sess,
		LocalAddress:      base.LocalInterface.Ip4,
		Stat:              &stat{0, 0},
		closeOnce:         sync.Once{},
		CloseChan:         make(chan struct{}),
		DtlsSetupChan:     make(chan struct{}),
		PayloadIn:         make(chan *proto.Payload, 64),
		PayloadOutTLS:     make(chan *proto.Payload, 64),
		PayloadOutDTLS:    make(chan *proto.Payload, 64),
		DtlsConnected:     atomic.NewBool(false),
		ResetTLSReadDead:  atomic.NewBool(true),
		ResetDTLSReadDead: atomic.NewBool(true),
		DSess: &DtlsSession{
			closeOnce: sync.Once{},
			CloseChan: make(chan struct{}),
		},
	}
	sess.CSess = cSess

	sess.ActiveClose = false
	sess.CloseChan = make(chan struct{})

	cSess.VPNAddress = header.Get("X-CSTP-Address")
	cSess.VPNMask = header.Get("X-CSTP-Netmask")
	cSess.MTU, _ = strconv.Atoi(header.Get("X-CSTP-MTU"))
	cSess.DNS = header.Values("X-CSTP-DNS")
	// 如果服务器下发空字符串，字符串数组不会为 nil，会导致解析ip时报错
	cSess.SplitInclude = header.Values("X-CSTP-Split-Include")
	cSess.SplitExclude = header.Values("X-CSTP-Split-Exclude")
	// debug with https://ip.900cha.com/
	// cSess.SplitExclude = append(cSess.SplitExclude, "47.243.165.103/255.255.255.255")

	cSess.TLSDpdTime, _ = strconv.Atoi(header.Get("X-CSTP-DPD"))
	cSess.TLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-CSTP-Keepalive"))
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.1.5.1
	cSess.DTLSId = header.Get("X-DTLS-Session-ID")
	if cSess.DTLSId == "" {
		// 兼容最新 ocserv
		cSess.DTLSId = header.Get("X-DTLS-App-ID")
	}
	cSess.DTLSPort = header.Get("X-DTLS-Port")
	cSess.DTLSDpdTime, _ = strconv.Atoi(header.Get("X-DTLS-DPD"))
	cSess.DTLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-DTLS-Keepalive"))
	if base.Cfg.NoDTLS {
		cSess.DTLSCipherSuite = "Unknown"
	} else {
		cSess.DTLSCipherSuite = header.Get("X-DTLS12-CipherSuite") // 连接前后格式不同
	}

	cSess.CSTPCompression = proto.ParseCompression(header.Get("X-CSTP-Content-Encoding"))
	cSess.DTLSCompression = proto.ParseCompression(header.Get("X-DTLS-Content-Encoding"))
	// 仅协商压缩时启用统计，status 中未压缩时为 null
	if cSess.CSTPCompression != proto.CompNone || cSess.DTLSCompression != proto.CompNone {
		cSess.CompressStat = &CompressStat{}
	}

	// 会话超时/租期：与 openconnect 一致，取 Lease-Duration / Session-Timeout /
	// Session-Timeout-Remaining 中最小非零值作为到期时间；值可能为 "none"
	cSess.IdleTimeout, _ = strconv.Atoi(header.Get("X-CSTP-Idle-Timeout"))
	expiry := 0
	for _, v := range []int{
		atoiSafe(header.Get("X-CSTP-Lease-Duration")),
		atoiSafe(header.Get("X-CSTP-Session-Timeout")),
		atoiSafe(header.Get("X-CSTP-Session-Timeout-Remaining")),
	} {
		if v > 0 && (expiry == 0 || v < expiry) {
			expiry = v
		}
	}
	if expiry > 0 {
		cSess.AuthExpiration = time.Now().Add(time.Duration(expiry) * time.Second)
	}

	postAuth := header.Get("X-CSTP-Post-Auth-XML")
	if postAuth != "" {
		dtd := proto.DTD{}
		err := xml.Unmarshal([]byte(postAuth), &dtd)
		if err == nil {
			if dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains != "" {
				cSess.DynamicSplitIncludeDomains = strings.Split(dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains, ",")
				cSess.DynamicSplitTunneling = true
			} else if dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains != "" {
				// 字符串最后多一个逗号，导致数组最后一个元素为 ""，不排除配置错误其它元素也为空的可能，go 没有直接删除容器元素的方法，这里不处理
				cSess.DynamicSplitExcludeDomains = strings.Split(dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains, ",")
				cSess.DynamicSplitTunneling = true
			}

		}
	}

	return cSess
}

func (cSess *ConnSession) DPDTimer() {
	go func() {
		defer func() {
			base.Info("dead peer detection timer exit")
		}()
		base.Debug("TLSDpdTime:", cSess.TLSDpdTime, "TLSKeepaliveTime", cSess.TLSKeepaliveTime,
			"DTLSDpdTime", cSess.DTLSDpdTime, "DTLSKeepaliveTime", cSess.DTLSKeepaliveTime)
		// 简化处理，最小15秒检测一次,至少5秒冗余
		dpdTime := utils.Min(cSess.TLSDpdTime, cSess.DTLSDpdTime) - 5
		if dpdTime < 10 {
			dpdTime = 10
		}
		ticker := time.NewTicker(time.Duration(dpdTime) * time.Second)

		tlsDpd := proto.Payload{
			Type: 0x03,
			Data: make([]byte, 0, 8),
		}
		dtlsDpd := proto.Payload{
			Type: 0x03,
			Data: make([]byte, 0, 1),
		}

		for {
			select {
			case <-ticker.C:
				// base.Debug("dead peer detection")
				select {
				case cSess.PayloadOutTLS <- &tlsDpd:
				default:
				}
				if cSess.DtlsConnected.Load() {
					select {
					case cSess.PayloadOutDTLS <- &dtlsDpd:
					default:
					}
				}
			case <-cSess.CloseChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// ExpiryTimer 监控会话到期时间（X-CSTP-Lease-Duration / Session-Timeout 的最小值），
// 到期前 60 秒与到期时输出告警日志。断开后的自动重连由 rpc 层处理。
func (cSess *ConnSession) ExpiryTimer() {
	if cSess.AuthExpiration.IsZero() {
		return
	}
	go func() {
		defer func() {
			base.Info("session expiry timer exit")
		}()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				remaining := time.Until(cSess.AuthExpiration)
				switch {
				case remaining <= 0:
					base.Warn("session expired at", cSess.AuthExpiration.Format(time.RFC3339))
					return
				case remaining <= 60*time.Second:
					base.Warn("session will expire in", remaining.Round(time.Second))
				}
			case <-cSess.CloseChan:
				return
			}
		}
	}()
}

func (cSess *ConnSession) ReadDeadTimer() {
	go func() {
		defer func() {
			base.Info("read dead timer exit")
		}()
		// 避免每次 for 循环都重置读超时的时间
		// 这里是绝对时间，至于链接本身，服务器没有数据时 conn.Read 会阻塞，有数据时会不断判断
		ticker := time.NewTicker(4 * time.Second)
		for range ticker.C {
			select {
			case <-cSess.CloseChan:
				ticker.Stop()
				return
			default:
				cSess.ResetTLSReadDead.Store(true)
				cSess.ResetDTLSReadDead.Store(true)
			}
		}
	}()
}

func (cSess *ConnSession) Close() {
	cSess.closeOnce.Do(func() {
		if cSess.DtlsConnected.Load() {
			cSess.DSess.Close()
		}
		close(cSess.CloseChan)

		// 只清理仍指向本会话的全局状态。自动重连时旧会话的清理可能延迟执行
		//（例如 TLS 读卡在半个 TCP 连接上，网络恢复后才报错），若此时全局已
		// 指向新会话，绝不能置空或关闭新会话的通道，否则会触发误 ABORT、
		// 再次自动重连，并产生无人管理的孤儿会话（其 DTLS 通道会一直存活）。
		if Sess.CSess == cSess {
			Sess.CSess = nil
			close(Sess.CloseChan)
		}
	})
}

func (dSess *DtlsSession) Close() {
	dSess.closeOnce.Do(func() {
		close(dSess.CloseChan)
		// 与 ConnSession.Close 同理：仅当全局会话仍持有本 DtlsSession 时才
		// 修改其状态，避免旧会话的清理误清新会话的 DTLS 协商状态。
		if Sess.CSess != nil && Sess.CSess.DSess == dSess {
			Sess.CSess.DtlsConnected.Store(false)
			Sess.CSess.DTLSCipherSuite = ""
		}
	})
}
