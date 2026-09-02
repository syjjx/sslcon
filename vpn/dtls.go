package vpn

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"sslcon/base"
	"sslcon/proto"
	"sslcon/session"
)

// dtlsChannel 建立并维持 DTLS 隧道。
//
// DTLS 走 UDP，macOS 下网卡状态变化（DHCP 续租换 IP、WiFi 切换、休眠唤醒等）会让
// 已建立的 UDP socket 失效：继续 sendto 会报 EADDRNOTAVAIL（can't assign requested
// address），通道随即中断。本函数在通道中断或协商失败后按指数退避（5s→60s）自动
// 重建，直到会话关闭，避免 DTLS 中断后只能 TLS 单通道运行、且永远无法恢复。
func dtlsChannel(cSess *session.ConnSession) {
	defer base.Info("dtls channel exit")

	var (
		dead = time.Duration(cSess.DTLSDpdTime+5) * time.Second
	)

	port, _ := strconv.Atoi(cSess.DTLSPort)
	addr := &net.UDPAddr{IP: net.ParseIP(cSess.ServerAddress), Port: port}

	id, _ := hex.DecodeString(cSess.DTLSId)

	config := &dtls.Config{
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
		CipherSuites: func() []dtls.CipherSuiteID {
			switch cSess.DTLSCipherSuite {
			case "ECDHE-ECDSA-AES128-GCM-SHA256":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			case "ECDHE-RSA-AES128-GCM-SHA256":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
			case "ECDHE-ECDSA-AES256-GCM-SHA384":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
			case "ECDHE-RSA-AES256-GCM-SHA384":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
			default:
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			}
		}(),
		SessionStore: &SessionStore{dtls.Session{ID: id, Secret: session.Sess.PreMasterSecret}},
		// PSK: func(hint []byte) ([]byte, error) {
		//     // return []byte{0xAB, 0xC1, 0x23}, nil
		//     return id, nil
		// },
		// PSKIdentityHint: id,
	}

	// DtlsSetupChan 用于通知 STATUS RPC "首次 DTLS 协商已出结果"（无论成功失败），
	// 只能关闭一次；任何退出路径都要保证它被关闭，否则 STATUS 会永久阻塞。
	setupClosed := false
	closeSetup := func() {
		if !setupClosed {
			setupClosed = true
			close(cSess.DtlsSetupChan)
		}
	}
	defer closeSetup()

	delay := 5 * time.Second
	for {
		select {
		case <-cSess.CloseChan:
			return
		default:
		}

		conn, err := dtls.Dial("udp4", addr, config)
		// https://github.com/pion/dtls/pull/649
		if err != nil {
			base.Error("dtls dial error:", err)
			closeSetup()
			base.Warn("dtls negotiation failed, retry in", delay)
			if !dtlsRetryWait(cSess, &delay) {
				return
			}
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err = conn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			base.Error("dtls handshake error:", err)
			_ = conn.Close()
			closeSetup()
			base.Warn("dtls negotiation failed, retry in", delay)
			if !dtlsRetryWait(cSess, &delay) {
				return
			}
			continue
		}

		closeSetup()
		cSess.DtlsConnected.Store(true)
		cSess.ResetDTLSReadDead.Store(true) // 新通道立即设置读超时

		// rewrite cSess.DTLSCipherSuite
		state, success := conn.ConnectionState()
		if success {
			cSess.DTLSCipherSuite = dtls.CipherSuiteName(state.CipherSuiteID)
		} else {
			cSess.DTLSCipherSuite = ""
		}

		base.Info("dtls channel negotiation succeeded")
		delay = 5 * time.Second // 成功后重置退避，下次波动从 5s 重新开始

		// 阻塞运行已建立的通道；返回 true 表示会话已关闭，false 表示通道中断
		if sessionClosed := runDtlsEstablished(conn, cSess, dead); sessionClosed {
			return
		}

		// 通道中断（如 UDP 发送 EADDRNOTAVAIL）：切换回 TLS 通道，退避后重建
		cSess.DtlsConnected.Store(false)
		cSess.DTLSCipherSuite = ""
		base.Warn("dtls channel lost, retry in", delay)
		if !dtlsRetryWait(cSess, &delay) {
			return
		}
	}
}

// dtlsRetryWait 按指数退避等待下一次 DTLS 重建（5s 起，60s 封顶）。
// 会话已关闭时返回 false，调用方应退出。
func dtlsRetryWait(cSess *session.ConnSession, delay *time.Duration) bool {
	timer := time.NewTimer(*delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		if *delay < 60*time.Second {
			*delay *= 2
		}
		return true
	case <-cSess.CloseChan:
		return false
	}
}

// runDtlsEstablished 运行已建立的 DTLS 通道：读取服务端数据并转发到
// cSess.PayloadIn，同时启动发送协程。阻塞直到通道中断或会话关闭。
// 返回 true 表示会话已关闭（调用方应退出），false 表示通道中断（调用方应重建）。
func runDtlsEstablished(conn *dtls.Conn, cSess *session.ConnSession, dead time.Duration) bool {
	// attemptDone 通知本通道的发送协程退出：通道被拆除时（如读侧先失败）由本
	// 函数关闭；会话关闭时由 cSess.DSess.CloseChan 通知。避免重建后旧发送协程
	// 继续从 PayloadOutDTLS 取包写到已关闭的连接上。
	attemptDone := make(chan struct{})
	defer close(attemptDone)
	defer func() {
		_ = conn.Close()
	}()

	// 解压缓冲：解压后的包可能大于协商 MTU，预留 16KB
	decompressBuf := make([]byte, 16384)

	go payloadOutDTLSToServer(conn, cSess, attemptDone)

	// Step 21 serverToPayloadIn
	// 读取服务器返回的数据，调整格式，放入 cSess.PayloadIn，不再用子协程是为了能够退出 dtlsChannel 协程
	for {
		// 重置超时限制
		if cSess.ResetDTLSReadDead.Load() {
			_ = conn.SetReadDeadline(time.Now().Add(dead))
			cSess.ResetDTLSReadDead.Store(false)
		}

		pl := getPayloadBuffer()                 // 从池子申请一块内存，存放去除头部的数据包到 PayloadIn，在 payloadInToTun 中释放
		bytesReceived, err := conn.Read(pl.Data) // 服务器没有数据返回时，会阻塞
		if err != nil {
			base.Error("dtls server to payloadIn error:", err)
			return false
		}

		// base.Debug("dtls server to payloadIn")
		// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.3
		// UDP 数据包的头部只有 1 字节
		switch pl.Data[0] {
		case 0x07: // KEEPALIVE
			// base.Debug("dtls receive KEEPALIVE")
		case 0x05: // DISCONNECT
			// base.Debug("dtls receive DISCONNECT")
			return false
		case 0x03: // DPD-REQ
			// base.Debug("dtls receive DPD-REQ")
			pl.Type = 0x04
			select {
			case cSess.PayloadOutDTLS <- pl:
			case <-cSess.DSess.CloseChan:
				return true
			}
		case 0x04:
			base.Debug("dtls receive DPD-RESP")
		case 0x00: // DATA
			wire := int64(bytesReceived - 1)
			if cSess.DTLSCompression != proto.CompNone {
				atomic.AddInt64(&cSess.CompressStat.RecvWire, wire)
				atomic.AddInt64(&cSess.CompressStat.RecvOriginal, wire)
			}
			pl.Data = append(pl.Data[:0], pl.Data[1:bytesReceived]...)
			select {
			case cSess.PayloadIn <- pl:
			case <-cSess.DSess.CloseChan:
				return true
			}
		case 0x08: // COMPRESSED DATA
			// base.Debug("dtls receive COMPRESSED DATA")
			n, derr := proto.DecompressData(cSess.DTLSCompression, pl.Data[1:bytesReceived], decompressBuf)
			if derr != nil {
				base.Error("dtls decompress error:", derr)
				return false
			}
			if cSess.DTLSCompression != proto.CompNone {
				atomic.AddInt64(&cSess.CompressStat.RecvWire, int64(bytesReceived-1))
				atomic.AddInt64(&cSess.CompressStat.RecvOriginal, int64(n))
			}
			pl.Data = append(pl.Data[:0], decompressBuf[:n]...)
			select {
			case cSess.PayloadIn <- pl:
			case <-cSess.DSess.CloseChan:
				return true
			}
		}
		cSess.Stat.BytesReceived += uint64(bytesReceived)
	}
}

// payloadOutDTLSToServer Step 4
func payloadOutDTLSToServer(conn *dtls.Conn, cSess *session.ConnSession, attemptDone chan struct{}) {
	defer func() {
		base.Info("dtls payloadOut to server exit")
		_ = conn.Close()
		// 注意：这里不再关闭 dSess。dSess.CloseChan 是会话级 DTLS 关闭信号，
		// 仅由 cSess.Close() 关闭；通道中断后重建时还需要复用同一个 dSess。
	}()

	var (
		err       error
		bytesSent int
		pl        *proto.Payload
	)
	// 压缩缓冲：2048*9/8 最坏情况约 2304，预留 4096
	compressBuf := make([]byte, 4096)

	for {
		select {
		case pl = <-cSess.PayloadOutDTLS:
		case <-cSess.DSess.CloseChan:
			return
		case <-attemptDone:
			return
		}

		// base.Debug("dtls payloadOut to server")
		if pl.Type == 0x00 {
			// 获取数据长度
			l := len(pl.Data)
			compressed := false
			// 协商了压缩则尝试压缩（压缩后更大则发原始数据，接收端两者都支持）
			if cSess.DTLSCompression != proto.CompNone {
				original := l
				if n, cerr := proto.CompressData(cSess.DTLSCompression, pl.Data, compressBuf); cerr == nil && n < l {
					pl.Data = append(pl.Data[:0], compressBuf[:n]...)
					l = n
					compressed = true
				}
				// 压缩统计（原子计数，开销可忽略）
				atomic.AddInt64(&cSess.CompressStat.SendOriginal, int64(original))
				atomic.AddInt64(&cSess.CompressStat.SendWire, int64(l))
			}
			// 先扩容 +1
			pl.Data = pl.Data[:l+1]
			// 数据后移
			copy(pl.Data[1:], pl.Data)
			// 添加头信息（0x08 压缩数据）
			if compressed {
				pl.Data[0] = 0x08
			} else {
				pl.Data[0] = pl.Type
			}
		} else {
			// 设置头类型
			pl.Data = append(pl.Data[:0], pl.Type)
		}

		bytesSent, err = conn.Write(pl.Data)
		if err != nil {
			base.Error("dtls payloadOut to server error:", err)
			return
		}
		cSess.Stat.BytesSent += uint64(bytesSent)

		// 释放由 tunToPayloadOut 申请的内存
		putPayloadBuffer(pl)
	}
}

type SessionStore struct {
	sess dtls.Session
}

func (store *SessionStore) Set([]byte, dtls.Session) error {
	return nil
}

func (store *SessionStore) Get([]byte) (dtls.Session, error) {
	return store.sess, nil
}

func (store *SessionStore) Del([]byte) error {
	return nil
}
