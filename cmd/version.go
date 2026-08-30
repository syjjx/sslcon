package cmd

import (
	"fmt"
	"runtime"

	"github.com/apieasy/gson"
	"github.com/spf13/cobra"
	"sslcon/base"
	"sslcon/rpc"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("sslcon client:", base.Version)
		if base.Commit != "" {
			fmt.Println("commit:", base.Commit)
		}
		fmt.Println("go:", runtime.Version())

		// 查询运行中的 vpnagent 版本（判断是否需要更新）
		result := gson.New()
		err := rpcCall("version", nil, result, rpc.VERSION)
		if err != nil {
			fmt.Println("vpnagent: not reachable:", err)
			return
		}
		fmt.Println("vpnagent running:", result.String())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
