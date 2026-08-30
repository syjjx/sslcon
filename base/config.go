package base

var (
	Cfg            = &ClientConfig{}
	LocalInterface = &Interface{}
)

type ClientConfig struct {
	LogLevel           string `json:"log_level"`
	LogPath            string `json:"log_path"`
	InsecureSkipVerify bool   `json:"skip_verify"`
	CiscoCompat        bool   `json:"cisco_compat"`
	NoDTLS             bool   `json:"no_dtls"`
	AgentName          string `json:"agent_name"`
	AgentVersion       string `json:"agent_version"`
	Compression        bool   `json:"compression"`   // 是否协商数据压缩（oc-lz4/lzs）
	AutoReconnect      bool   `json:"auto_reconnect"` // 异常断线自动重连（指数退避）
}

// Interface 应该由外部接口设置
type Interface struct {
	Name    string `json:"name"`
	Ip4     string `json:"ip4"`
	Mac     string `json:"mac"`
	Gateway string `json:"gateway"`
}

func initCfg() {
	Cfg.LogLevel = "Debug"
	Cfg.InsecureSkipVerify = true
	Cfg.CiscoCompat = true
	Cfg.AgentName = ""
	Cfg.AgentVersion = "4.10.07062"
	Cfg.Compression = true
	Cfg.AutoReconnect = true
}
