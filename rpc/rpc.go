package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"go.uber.org/atomic"
	"sslcon/auth"
	"sslcon/base"
	"sslcon/proto"
	"sslcon/session"

	"github.com/gorilla/websocket"
	"github.com/sourcegraph/jsonrpc2"
	ws "github.com/sourcegraph/jsonrpc2/websocket"
)

const (
	STATUS = iota
	CONFIG
	CONNECT
	DISCONNECT
	RECONNECT
	INTERFACE
	ABORT
	STAT
	VERSION
)

var (
	Clients         []*jsonrpc2.Conn
	rpcHandler      = handler{}
	connectedStr    string
	disconnectedStr string
	autoReconnecting atomic.Bool // 自动重连进行中标志
)

// statReply STAT 接口的返回：原有流量统计 + 压缩统计 + 压缩协商状态
type statReply struct {
	BytesSent       uint64                `json:"bytesSent"`
	BytesReceived   uint64                `json:"bytesReceived"`
	CompressStat    *session.CompressStat `json:"compress_stat"`
	CSTPCompression proto.Compression     `json:"cstp_compression"`
	DTLSCompression proto.Compression     `json:"dtls_compression"`
}

// versionReply VERSION 接口返回：运行中的 vpnagent 构建信息
type versionReply struct {
	Version      string `json:"version"`       // sslcon 构建版本
	Commit       string `json:"commit"`        // git commit（可空）
	AgentVersion string `json:"agent_version"` // 上报给服务端的 AnyConnect 客户端版本
	GoVersion    string `json:"go_version"`    // 编译所用 Go 版本
}

type handler struct{}

func Setup() {
	go func() {
		http.HandleFunc("/rpc", rpc)
		// 无法启动则退出服务或应用，监听本地不需要有效物理网卡
		log.Println("rpc server start :6210")
		base.Fatal(http.ListenAndServe(":6210", nil))
	}()
}

func rpc(resp http.ResponseWriter, req *http.Request) {
	base.Debug("rpc request:", req)
	up := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	conn, err := up.Upgrade(resp, req, nil)
	if err != nil {
		base.Error(err)
		return
	}
	defer conn.Close()

	jsonStream := ws.NewObjectStream(conn)
	// 此时 base.GetBaseLogger() 仍然是 Stdout，当前使用的 rpc 库无法在连接成功后修改 logger
	rpcConn := jsonrpc2.NewConn(req.Context(), jsonStream, &rpcHandler, jsonrpc2.SetLogger(base.GetBaseLogger()))
	Clients = append(Clients, rpcConn)
	<-rpcConn.DisconnectNotify()
	for i, c := range Clients {
		if c == rpcConn {
			Clients = append(Clients[:i], Clients[i+1:]...)
			base.Debug(fmt.Sprintf("client %d disconnected", i))
			break
		}
	}
}

// Handle ID 即方法
func (_ *handler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	defer func() {
		if err := recover(); err != nil {
			base.Error(string(debug.Stack()))
		}
	}()

	// request route
	switch req.ID.Num {
	case STAT:
		// 未连接之前不应该调用这里
		if session.Sess.CSess != nil {
			cSess := session.Sess.CSess
			_ = conn.Reply(ctx, req.ID, statReply{
				BytesSent:       cSess.Stat.BytesSent,
				BytesReceived:   cSess.Stat.BytesReceived,
				CompressStat:    cSess.CompressStat,
				CSTPCompression: cSess.CSTPCompression,
				DTLSCompression: cSess.DTLSCompression,
			})
			return
		}
		jError := jsonrpc2.Error{Code: 1, Message: disconnectedStr}
		_ = conn.ReplyWithError(ctx, req.ID, &jError)
	case VERSION:
		// 不依赖连接状态，随时可查：用于判断运行中的 vpnagent 是否需要更新
		_ = conn.Reply(ctx, req.ID, versionReply{
			Version:      base.Version,
			Commit:       base.Commit,
			AgentVersion: base.Cfg.AgentVersion,
			GoVersion:    runtime.Version(),
		})
	case STATUS:
		// 未连接之前不应该调用这里
		if session.Sess.CSess != nil {
			if !base.Cfg.NoDTLS && session.Sess.CSess.DTLSPort != "" {
				// 等待 DTLS 隧道创建过程结束，无论隧道是否建立成功
				<-session.Sess.CSess.DtlsSetupChan
			}

			if session.Sess.CSess != nil {
				_ = conn.Reply(ctx, req.ID, session.Sess.CSess)
				return
			}
		}

		jError := jsonrpc2.Error{Code: 1, Message: disconnectedStr}
		_ = conn.ReplyWithError(ctx, req.ID, &jError)
	case CONNECT:
		base.Debug("CONNECT")
		if autoReconnecting.Load() {
			jError := jsonrpc2.Error{Code: 1, Message: "auto reconnecting, please wait"}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		// 启动时未连接，其它 UI 连接后再次调用
		if session.Sess.CSess != nil {
			_ = conn.Reply(ctx, req.ID, connectedStr)
			return
		}
		err := json.Unmarshal(*req.Params, auth.Prof)
		if err != nil {
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		err = Connect()
		if err != nil {
			base.Error(err)
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			DisConnect()
			return
		}
		connectedStr = "connected to " + auth.Prof.Host
		disconnectedStr = "disconnected from " + auth.Prof.Host
		_ = conn.Reply(ctx, req.ID, connectedStr)
		go monitor()
	case RECONNECT:
		base.Debug("RECONNECT")
		// UI 未检测到活动网络发生变化或者网络变化后已经推送接口信息
		if session.Sess.CSess != nil {
			_ = conn.Reply(ctx, req.ID, connectedStr)
			return
		}
		err := SetupTunnel(true)
		if err != nil {
			base.Error(err)
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			DisConnect()
			return
		}
		_ = conn.Reply(ctx, req.ID, connectedStr)
		go monitor()
	case DISCONNECT:
		base.Debug("DISCONNECT")
		if session.Sess.CSess != nil {
			DisConnect()
		} else {
			jError := jsonrpc2.Error{Code: 1, Message: disconnectedStr}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
		}
	case CONFIG:
		// 初始化配置
		log.Println("CONFIG")
		err := json.Unmarshal(*req.Params, &base.Cfg)
		if err != nil {
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		_ = conn.Reply(ctx, req.ID, "ready to connect")
		// 每次重启客户端或者配置更改，重置 logger（按 log_path/log_level 写日志文件）
		base.InitLog()
	case INTERFACE:
		base.Debug("INTERFACE")
		err := json.Unmarshal(*req.Params, base.LocalInterface)
		if err != nil {
			jError := jsonrpc2.Error{Code: 1, Message: err.Error()}
			_ = conn.ReplyWithError(ctx, req.ID, &jError)
			return
		}
		auth.Prof.Initialized = true
		_ = conn.Reply(ctx, req.ID, "ready to connect")
	default:
		base.Debug("receive rpc call:", req)
		jError := jsonrpc2.Error{Code: 1, Message: "unknown method: " + req.Method}
		_ = conn.ReplyWithError(ctx, req.ID, &jError)
	}
}

func monitor() {
	// 不考虑 DTLS 中途关闭情形
	<-session.Sess.CloseChan
	ctx := context.Background()
	for _, conn := range Clients {
		if session.Sess.ActiveClose {
			_ = conn.Reply(ctx, jsonrpc2.ID{Num: DISCONNECT, IsString: false}, disconnectedStr)
		} else {
			_ = conn.Reply(ctx, jsonrpc2.ID{Num: ABORT, IsString: false}, disconnectedStr)
		}
	}
	// 异常断开（非用户主动）且开启自动重连时，指数退避重连
	if !session.Sess.ActiveClose && base.Cfg.AutoReconnect {
		startAutoReconnect()
	}
}

// startAutoReconnect 指数退避自动重连：1s 起，翻倍至 60s 封顶，
// 直到重连成功或用户主动断开（ActiveClose）
func startAutoReconnect() {
	if !autoReconnecting.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer autoReconnecting.Store(false)
		delay := 1 * time.Second
		for {
			if session.Sess.ActiveClose {
				return
			}
			base.Info("auto reconnect in", delay)
			time.Sleep(delay)
			if session.Sess.ActiveClose {
				return
			}
			base.Info("auto reconnect attempt")
			if err := reconnectOnce(); err != nil {
				base.Error("auto reconnect failed:", err)
				delay *= 2
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				continue
			}
			// 重连成功的瞬间用户可能已请求断开
			if session.Sess.ActiveClose {
				DisConnect()
				return
			}
			base.Info("auto reconnect succeeded")
			connectedStr = "connected to " + auth.Prof.Host
			go monitor()
			return
		}
	}()
}

// reconnectOnce 完整重连：重新认证 + 建立隧道（复用已填充的 Profile）
func reconnectOnce() error {
	if err := auth.InitAuth(); err != nil {
		return err
	}
	if err := auth.PasswordAuth(); err != nil {
		return err
	}
	return SetupTunnel(true)
}
