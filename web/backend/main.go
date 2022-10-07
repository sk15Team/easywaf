package main

import (
	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	"github.com/gogf/gf/v2/os/gctx"
	"waf/internal/cmd"
	"waf/scheduler"
)

func main() {
	scheduler.Run()
	cmd.Main.Run(gctx.New())
}
