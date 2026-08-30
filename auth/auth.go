package auth

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/elastic/go-sysinfo"
	"sslcon/base"
	"sslcon/proto"
	"sslcon/session"
	"sslcon/utils"
)

var (
	Prof         = &Profile{Initialized: false}
	Conn         *tls.Conn // tls.Conn 是结构体，net.Conn 是接口，所以这里可以用指针类型
	BufR         *bufio.Reader
	reqHeaders   = make(map[string]string)
	WebVpnCookie string
	// 认证阶段的会话 cookie。openconnect http.c 会把每次响应的 Set-Cookie 存起来
	// 并在后续请求回传 Cookie 头，ASA 可能依赖 init 响应下发的会话 cookie
	cookies = make(map[string]string)
)

// Profile 模板变量字段必须导出，虽然全局，但每次连接都被重置
type Profile struct {
	Host      string `json:"host"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Group     string `json:"group"`
	SecretKey string `json:"secret"`

	Initialized bool
	AppVersion  string // for report to server in xml
	// 上报给服务端的平台标识，取值与 openconnect 一致:
	// linux / linux-64 / win / mac-intel / android / apple-ios
	PlatformName string

	HostWithPort string
	Scheme       string
	AuthPath     string

	MacAddress  string
	TunnelGroup string
	GroupAlias  string
	ConfigHash  string

	ComputerName    string
	DeviceType      string
	PlatformVersion string
	UniqueId        string
}

const (
	tplInit = iota
	tplAuthReply
)

func init() {
	reqHeaders["X-Transcend-Version"] = "1"
	reqHeaders["X-Aggregate-Auth"] = "1"

	Prof.Scheme = "https://"

	host, _ := sysinfo.Host()
	info := host.Info()
	Prof.ComputerName = info.Hostname
	Prof.UniqueId = info.UniqueID

	os := info.OS
	Prof.DeviceType = os.Name
	if runtime.GOOS == "windows" {
		Prof.PlatformVersion = os.Build
	} else {
		Prof.PlatformVersion = strings.Split(os.Version, " ")[0]
	}
	Prof.PlatformName = platformName()
	// log.Printf("%+v %+v", info, os)
}

// platformName 与 openconnect_set_reported_os() 对齐，
// 真实 AnyConnect / ASA 校验 device-id 的文本内容，必须是这些取值之一
func platformName() string {
	switch runtime.GOOS {
	case "darwin":
		// openconnect 在 Apple Silicon 上也统一上报 mac-intel
		return "mac-intel"
	case "windows":
		return "win"
	case "android":
		return "android"
	case "ios":
		return "apple-ios"
	default:
		if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
			return "linux"
		}
		return "linux-64"
	}
}

// InitAuth 确定用户组和服务端认证地址 AuthPath
func InitAuth() error {
	WebVpnCookie = ""
	clear(cookies) // 每次新连接清空上次的会话 cookie
	// https://github.com/mwitkow/go-http-dialer
	config := tls.Config{
		InsecureSkipVerify: base.Cfg.InsecureSkipVerify,
	}
	var err error
	Conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp4", Prof.HostWithPort, &config)
	if err != nil {
		return err
	}
	BufR = bufio.NewReader(Conn)
	// base.Info(Conn.ConnectionState().Version)

	dtd := new(proto.DTD)

	Prof.AppVersion = base.Cfg.AgentVersion
	Prof.MacAddress = base.LocalInterface.Mac

	err = tplPost(tplInit, "", dtd)
	if err != nil {
		return err
	}
	Prof.AuthPath = dtd.Auth.Form.Action
	if Prof.AuthPath == "" {
		Prof.AuthPath = "/"
	}
	Prof.TunnelGroup = dtd.Opaque.TunnelGroup
	Prof.GroupAlias = dtd.Opaque.GroupAlias
	Prof.ConfigHash = dtd.Opaque.ConfigHash

	gps := len(dtd.Auth.Form.Groups)
	if gps != 0 && !utils.InArray(dtd.Auth.Form.Groups, Prof.Group) {
		return fmt.Errorf("available user groups are: %s", strings.Join(dtd.Auth.Form.Groups, " "))
	}

	return nil
}

// PasswordAuth 认证成功后，服务端新建 ConnSession，并生成 SessionToken 或者通过 Header 返回 WebVpnCookie
func PasswordAuth() error {
	dtd := new(proto.DTD)
	// 发送用户名或者用户名+密码
	err := tplPost(tplAuthReply, Prof.AuthPath, dtd)
	if err != nil {
		return err
	}
	// 兼容两步登陆，如必要则再次发送
	if dtd.Type == "auth-request" && dtd.Auth.Error.Value == "" {
		dtd = new(proto.DTD)
		err = tplPost(tplAuthReply, Prof.AuthPath, dtd)
		if err != nil {
			return err
		}
	}
	// 用户名、密码等错误
	if dtd.Type == "auth-request" {
		if dtd.Auth.Error.Value != "" {
			return fmt.Errorf(dtd.Auth.Error.Value, dtd.Auth.Error.Param1)
		}
		return errors.New(dtd.Auth.Message)
	}

	// AnyConnect 客户端支持 XML，OpenConnect 不使用 XML，而是使用 Cookie 反馈给客户端登陆状态
	session.Sess.SessionToken = dtd.SessionToken
	// 兼容 OpenConnect
	if WebVpnCookie != "" {
		session.Sess.SessionToken = WebVpnCookie
	}
	base.Debug("SessionToken:" + session.Sess.SessionToken)
	return nil
}

// 渲染模板并发送请求
func tplPost(typ int, path string, dtd *proto.DTD) error {
	tplBuffer := new(bytes.Buffer)
	if typ == tplInit {
		t, _ := template.New("init").Funcs(tplFuncs).Parse(templateInit)
		_ = t.Execute(tplBuffer, Prof)
	} else {
		t, _ := template.New("auth_reply").Funcs(tplFuncs).Parse(templateAuthReply)
		_ = t.Execute(tplBuffer, Prof)
	}
	if base.Cfg.LogLevel == "Debug" {
		post := tplBuffer.String()
		if typ == tplAuthReply {
			// 只隐藏密码，用户名保留可见，便于确认凭据确实发出
			post = passwordRegex.ReplaceAllString(post, "<password>***</password>")
		}
		base.Debug(post)
	}
	url := fmt.Sprintf("%s%s%s", Prof.Scheme, Prof.HostWithPort, path)
	if Prof.SecretKey != "" {
		url += "?" + Prof.SecretKey
	}
	req, _ := http.NewRequest("POST", url, tplBuffer)

	utils.SetCommonHeader(req)
	for k, v := range reqHeaders {
		req.Header[k] = []string{v}
	}
	// openconnect http_common_headers: Accept/Accept-Encoding 是认证阶段必须的头
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	// 回传之前响应里下发的会话 cookie（如 webvpn）
	if len(cookies) != 0 {
		var sb strings.Builder
		for k, v := range cookies {
			if sb.Len() > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(k + "=" + v)
		}
		req.Header.Set("Cookie", sb.String())
	}

	err := req.Write(Conn)
	if err != nil {
		Conn.Close()
		return err
	}

	var resp *http.Response
	resp, err = http.ReadResponse(BufR, req)
	if err != nil {
		Conn.Close()
		return err
	}
	defer resp.Body.Close()

	if base.Cfg.LogLevel == "Debug" {
		var hb bytes.Buffer
		_ = resp.Header.Write(&hb)
		base.Debug("response headers:\n" + hb.String())
	}
	// 收集会话 cookie，供后续请求回传（与 openconnect 行为一致）
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c.Value
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		Conn.Close()
		return err
	}
	if base.Cfg.LogLevel == "Debug" {
		base.Debug(string(body))
	}

	if resp.StatusCode == http.StatusOK {
		err = xml.Unmarshal(body, dtd)
		// ASA 认证失败时返回 200 + <config-auth type="complete"><error id="9x"/>，
		// 例如 "VPN Server could not parse request."，必须在这里显式报错，
		// 否则会拿着空 SessionToken 继续走隧道协商，产生误导性的 401
		if err == nil && dtd.Type == "complete" && (dtd.Error.Value != "" || dtd.Auth.Error.Value != "") {
			if dtd.Error.Value != "" {
				err = fmt.Errorf("auth error(%s): %s", dtd.Error.ID, dtd.Error.Value)
			} else {
				err = fmt.Errorf("auth error(%s): %s", dtd.Auth.Error.ID, dtd.Auth.Error.Value)
			}
			return err
		}
		if dtd.Type == "complete" && dtd.SessionToken == "" {
			// 兼容 ocserv
			cookies := resp.Cookies()
			if len(cookies) != 0 {
				for _, c := range cookies {
					if c.Name == "webvpn" {
						WebVpnCookie = c.Value
						break
					}
				}
			}
		}
		// nil
		return err
	}
	Conn.Close()
	return fmt.Errorf("auth error %s", resp.Status)
}

// tplFuncs 提供 XML 转义，防止服务端 opaque 回显内容含特殊字符时生成非法 XML
var tplFuncs = template.FuncMap{
	"xml": func(s string) string {
		var buf bytes.Buffer
		_ = xml.EscapeText(&buf, []byte(s))
		return buf.String()
	},
}

// passwordRegex 用于 Debug 日志中打码密码，避免明文泄露
var passwordRegex = regexp.MustCompile(`<password>.*?</password>`)

var templateInit = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>{{.PlatformName}}</device-id>
    <group-access>https://{{.HostWithPort}}/</group-access>
</config-auth>`

// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.2.2
// device-id 必须带文本内容（平台名），ASA 会严格校验；mac-address-list 仅旧版 HTML 表单流程需要，XML 流程不发
var templateAuthReply = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>{{.PlatformName}}</device-id>
    <opaque is-for="sg">
        <tunnel-group>{{xml .TunnelGroup}}</tunnel-group>
        <group-alias>{{xml .GroupAlias}}</group-alias>
        <config-hash>{{xml .ConfigHash}}</config-hash>
    </opaque>
    {{if .Group}}<group-select>{{xml .Group}}</group-select>{{end}}
    <auth>
        <username>{{xml .Username}}</username>
        <password>{{xml .Password}}</password>
    </auth>
</config-auth>`
