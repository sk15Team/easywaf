package cmd

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/net/goai"
	"github.com/gogf/gf/v2/os/gcmd"
	"waf/internal/consts"
	"waf/internal/controller"
	"waf/internal/service"
)



var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start easywaf http server ",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			s := g.Server()
			s.Use(ghttp.MiddlewareHandlerResponse)
			s.Group("/", func(group *ghttp.RouterGroup) {
				// Group middlewares.
				group.Middleware(
					service.Middleware().Ctx,
				)
				group.Middleware(MiddlewareCORS)
				controller.GfToken.Middleware(ctx, group)
				group.ALL("/api/public/rule", controller.Public.Rule)
				// Register route handlers.
				//group.Bind(
				//controller.User,
				//)
				// Special handler that needs authentication.
				group.Group("/api/v1", func(group *ghttp.RouterGroup) {

					group.ALL("/user/info", controller.User.Profile)
					group.ALL("/user/list", controller.User.List)
					group.ALL("/user/updatepass", controller.User.UpdatePass)
					group.ALL("/waf/setting/list", controller.Setting.List)
					group.ALL("/waf/setting/createvuln", controller.Setting.CreateVuln)
					group.ALL("/waf/setting/updatevuln", controller.Setting.UpdateVuln)
					group.ALL("/waf/setting/savemoduleswitch", controller.Setting.SaveModuleSwitch)
					group.ALL("/waf/setting/saveapiauth", controller.Setting.SaveApiAuth)
					group.ALL("/waf/setting/saverchain", controller.Setting.SaveRchain)
					group.ALL("/waf/setting/deletevuln", controller.Setting.DeleteVuln)
					group.ALL("/waf/setting/savecdn", controller.Setting.SaveCdn)
					group.ALL("/waf/setting/baselist", controller.Setting.BaseList)
					group.ALL("/waf/setting/savedenymsg", controller.Setting.SaveDenyMsg)
					group.ALL("/waf/setting/savelog", controller.Setting.SaveLog)
					group.ALL("/waf/setting/savees", controller.Setting.SaveEs)
					group.ALL("/waf/rule/list", controller.Rule.List)
					group.ALL("/waf/rule/create", controller.Rule.Create)
					group.ALL("/waf/rule/update", controller.Rule.Update)
					group.ALL("/waf/rule/delete", controller.Rule.Delete)
					group.ALL("/waf/app/list", controller.App.List)
					group.ALL("/waf/app/create", controller.App.Create)
					group.ALL("/waf/app/update", controller.App.Update)
					group.ALL("/waf/app/delete", controller.App.Delete)
					group.ALL("/waf/ip/list", controller.Ip.List)
					group.ALL("/waf/ip/create", controller.Ip.Create)
					group.ALL("/waf/ip/delete", controller.Ip.Delete)
					group.ALL("/waf/page/create", controller.Page.Create)
					group.ALL("/waf/page/list", controller.Page.List)
					group.ALL("/waf/page/update", controller.Page.Update)
					group.ALL("/waf/page/delete", controller.Page.Delete)
					group.ALL("/waf/log/list", controller.Log.List)
					group.ALL("/waf/dashboard/list", controller.Dashboard.List)
					group.ALL("/waf/dashboard/line", controller.Dashboard.Line)
				})
			})
			// Custom enhance API document.
			enhanceOpenAPIDoc(s)
			// Just run the server.
			s.Run()
			return nil
		},
	}
)

func MiddlewareCORS(r *ghttp.Request) {
	r.Response.CORSDefault()
	r.Middleware.Next()
}


func enhanceOpenAPIDoc(s *ghttp.Server) {
	openapi := s.GetOpenApi()
	openapi.Config.CommonResponse = ghttp.DefaultHandlerResponse{}
	openapi.Config.CommonResponseDataField = `Data`

	// API description.
	openapi.Info = goai.Info{
		Title:       consts.OpenAPITitle,
		Description: consts.OpenAPIDescription,
		Contact: &goai.Contact{
			Name: "GoFrame",
			URL:  "https://goframe.org",
		},
	}
}
