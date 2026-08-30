package auth

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"text/template"

	"sslcon/proto"
)

func parseDTD(body []byte) (*proto.DTD, error) {
	dtd := new(proto.DTD)
	err := xml.Unmarshal(body, dtd)
	return dtd, err
}

// 验证 init 模板渲染结果，防止模板错误被 t.Execute 的忽略吞掉
func TestRenderTemplateInit(t *testing.T) {
	p := &Profile{
		AppVersion:   "4.10.07062",
		PlatformName: "mac-intel",
		HostWithPort: "vpn.example.com:443",
	}
	buf := new(bytes.Buffer)
	tpl, err := template.New("init").Funcs(tplFuncs).Parse(templateInit)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpl.Execute(buf, p); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`type="init"`,
		`<device-id>mac-intel</device-id>`,
		`<group-access>https://vpn.example.com:443/</group-access>`,
		`<version who="vpn">4.10.07062</version>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("init 模板缺少 %q\n实际输出:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<no value>") {
		t.Errorf("init 模板存在未渲染字段\n%s", out)
	}
}

// 验证 auth-reply 模板：带 group、无 group、特殊字符转义三种情况
func TestRenderTemplateAuthReply(t *testing.T) {
	cases := []struct {
		name      string
		group     string
		opaqueVal string
		wantGroup bool
	}{
		{"with group", "RA", "hash&more", true},
		{"no group", "", "plain", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &Profile{
				AppVersion:   "4.10.07062",
				PlatformName: "mac-intel",
				Group:        c.group,
				TunnelGroup:  "RA",
				GroupAlias:   "RA",
				ConfigHash:   c.opaqueVal,
				Username:     "user",
				Password:     "pass",
			}
			buf := new(bytes.Buffer)
			tpl, err := template.New("auth_reply").Funcs(tplFuncs).Parse(templateAuthReply)
			if err != nil {
				t.Fatal(err)
			}
			if err := tpl.Execute(buf, p); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			for _, want := range []string{
				`type="auth-reply"`,
				`<device-id>mac-intel</device-id>`,
				`<username>user</username>`,
				`<password>pass</password>`,
				`<tunnel-group>RA</tunnel-group>`,
			} {
				if !strings.Contains(out, want) {
					t.Errorf("auth-reply 模板缺少 %q\n实际输出:\n%s", want, out)
				}
			}
			if strings.Contains(out, "<no value>") {
				t.Errorf("auth-reply 模板存在未渲染字段\n%s", out)
			}
			if c.wantGroup && !strings.Contains(out, "<group-select>RA</group-select>") {
				t.Errorf("应包含 group-select\n%s", out)
			}
			if !c.wantGroup && strings.Contains(out, "group-select") {
				t.Errorf("未传 group 时不应输出 group-select\n%s", out)
			}
			// 特殊字符必须被转义为合法 XML
			if strings.Contains(out, "hash&more") && !strings.Contains(out, "hash&amp;more") {
				t.Errorf("config-hash 未做 XML 转义\n%s", out)
			}
			if strings.Contains(out, "mac-address-list") {
				t.Errorf("auth-reply 不应再包含 mac-address-list\n%s", out)
			}
		})
	}
}

// 验证 ASA 错误响应（<error> 为 config-auth 直接子元素）能被 DTD 正确解析
func TestParseASAAuthError(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<error id="98" param1="" param2="">VPN Server could not parse request.</error>
</config-auth>`
	dtd, err := parseDTD([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if dtd.Type != "complete" {
		t.Errorf("Type = %q, want complete", dtd.Type)
	}
	if dtd.Error.ID != "98" || !strings.Contains(dtd.Error.Value, "could not parse") {
		t.Errorf("Error = %+v", dtd.Error)
	}
}

// 验证 ocserv 成功响应（webvpn cookie + session-token）不被误判为错误
func TestParseSuccessResponse(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>abc123</session-token>
</config-auth>`
	dtd, err := parseDTD([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if dtd.Error.Value != "" {
		t.Errorf("成功响应不应解析出 error: %+v", dtd.Error)
	}
	if dtd.SessionToken != "abc123" {
		t.Errorf("SessionToken = %q", dtd.SessionToken)
	}
}
