package controller

import (
	"github.com/goflyfox/gtoken/gtoken"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"waf/internal/dao"
)
// 启动gtoken
var GfToken = &gtoken.GfToken{
	LoginPath:       "/api/v1/user/sign-in",
	LoginBeforeFunc: Login,
	LogoutPath:      "/api/v1/user/sign-out",
	AuthExcludePaths: g.SliceStr{"/api/public/rule",
		"/api/v1/user/info"}, // 不拦截路径
}

var User = cUser{}

type cUser struct{}

//登陆函数
func Login(r *ghttp.Request) (string, interface{}) {
	username := r.Get("Passport").String()
	passwd ,_:= gmd5.EncryptString(r.Get("password").String())

	// TODO 进行登录校验
	searchList := g.Map{
		"passport": username,
		"password": passwd,
	}

	LoginC, err := dao.User.DB().Model("user").Where(searchList).One()
	if err != nil {
		r.Response.WriteJson(gtoken.Fail(err.Error()))
		r.ExitAll()
	}
	if LoginC.IsEmpty() == true {
		r.Response.WriteJson(gtoken.Fail("账号或密码错误."))
		r.ExitAll()
	}

	return username, ""
}

func (c *cUser) Profile(r *ghttp.Request) {

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{
			"avatar":       "https://s1.ax1x.com/2022/08/18/vD4wCT.jpg",
			"introduction": "WAF Manager",
			"name":         "管理员大人",
			"roles":        "admin",
		},
	})

}

func (c *cUser) List(r *ghttp.Request) {

	//查找当前用户
	LoginUser := GfToken.GetTokenData(r).Get("userKey")

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{
			"User":  g.Map{"username":LoginUser},
		},
	})

}

func (c *cUser) UpdatePass(r *ghttp.Request) {

	username := r.Get("username").String()
	passwd ,_:= gmd5.EncryptString(r.Get("password").String())
	new_password ,_ := gmd5.EncryptString(r.Get("new_password").String())

	// TODO 进行登录校验
	searchList := g.Map{
		"passport": username,
		"password": passwd,
	}

	LoginC, err := dao.User.DB().Model("user").Where(searchList).One()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if LoginC.IsEmpty() == true {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg": "账号或密码错误.",
			"data": "",
		})
	}

	Result, err := dao.User.DB().Model("user").Where(searchList).Update(g.Map{"password": new_password})
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{
			"success":  Result,
		},
	})

}