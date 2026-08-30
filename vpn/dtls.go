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

// 新建 dtls.Conn
func dtlsChannel(cSess *session.ConnSession) {
	var (
		conn          *dtls.Conn
		dSess         *session.DtlsSession
		err           error
		bytesReceived int
		dead          = time.Duration(cSess.DTLSDpdTime+5) * time.Second
	)
	defer func() {
		base.Info("dtls channel exit")
		if conn != nil {
			_ = conn.Close()
		}
		if dSess != nil {
			dSess.Close()
		}
	}()

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

	conn, err = dtls.Dial("udp4", addr, config)
	// https://github.com/pion/dtls/pull/649
	if err != nil {
		base.Error(err)
		close(cSess.DtlsSetupChan) // 没有成功建立 DTLS 隧道
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = conn.HandshakeContext(ctx); err != nil {
		base.Error(err)
		close(cSess.DtlsSetupChan) // 没有成功建立 DTLS 隧道
		return
	}

	cSess.DtlsConnected.Store(true)
	dSess = cSess.DSess
	close(cSess.DtlsSetupChan) // 成功建立 DTLS 隧道

	// rewrite cSess.DTLSCipherSuite
	state, success := conn.ConnectionState()
	if success {
		cSess.DTLSCipherSuite = dtls.CipherSuiteName(state.CipherSuiteID)
	} else {
		cSess.DTLSCipherSuite = ""
	}

	base.Info("dtls channel negotiation succeeded")

	go payloadOutDTLSToServer(conn, dSess, cSess)

	// 解压缓冲：解压后的包可能大于协商 MTU，预留 16KB
	decompressBuf := make([]byte, 16384)

	// Step 21 serverToPayloadIn
	// 读取服务器返回的数据，调整格式，放入 cSess.PayloadIn，不再用子协程是为了能够退出 dtlsChannel 协程
	for {
		// 重置超时限制
		if cSess.ResetDTLSReadDead.Load() {
			_ = conn.SetReadDeadline(time.Now().Add(dead))
			cSess.ResetDTLSReadDead.Store(false)
		}

		pl := getPayloadBuffer()                // 从池子申请一块内存，存放去除头部的数据包到 PayloadIn，在 payloadInToTun 中释放
		bytesReceived, err = conn.Read(pl.Data) // 服务器没有数据返回时，会阻塞
		if err != nil {
			base.Error("dtls server to payloadIn error:", err)
			return
		}

		// base.Debug("dtls server to payloadIn")
		// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.3
		// UDP 数据包的头部只有 1 字节
		switch pl.Data[0] {
		case 0x07: // KEEPALIVE
			// base.Debug("dtls receive KEEPALIVE")
		case 0x05: // DISCONNECT
			// base.Debug("dtls receive DISCONNECT")
			return
		case 0x03: // DPD-REQ
			// base.Debug("dtls receive DPD-REQ")
			pl.Type = 0x04
			select {
			case cSess.PayloadOutDTLS <- pl:
			case <-dSess.CloseChan:
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
			case <-dSess.CloseChan:
				return
			}
		case 0x08: // COMPRESSED DATA
			// base.Debug("dtls receive COMPRESSED DATA")
			n, derr := proto.DecompressData(cSess.DTLSCompression, pl.Data[1:bytesReceived], decompressBuf)
			if derr != nil {
				base.Error("dtls decompress error:", derr)
				return
			}
			if cSess.DTLSCompression != proto.CompNone {
				atomic.AddInt64(&cSess.CompressStat.RecvWire, int64(bytesReceived-1))
				atomic.AddInt64(&cSess.CompressStat.RecvOriginal, int64(n))
			}
			pl.Data = append(pl.Data[:0], decompressBuf[:n]...)
			select {
			case cSess.PayloadIn <- pl:
			case <-dSess.CloseChan:
				return
			}
		}
		cSess.Stat.BytesReceived += uint64(bytesReceived)
	}
}

// payloadOutDTLSToServer Step 4
func payloadOutDTLSToServer(conn *dtls.Conn, dSess *session.DtlsSession, cSess *session.ConnSession) {
	defer func() {
		base.Info("dtls payloadOut to server exit")
		_ = conn.Close()
		dSess.Close()
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
		case <-dSess.CloseChan:
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
