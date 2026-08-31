package base

// 版本信息：构建时可用 -ldflags "-X sslcon/base.Version=x.y.z" 注入，
// 未注入时使用默认值。发布新版本时请同步递增版本号。
var Version = "2.1.1"

// Commit 构建时的 git commit（可选，由 -ldflags 注入）
var Commit = ""
