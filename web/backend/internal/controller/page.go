package controller

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"waf/internal/dao"
)

var Page = cPage{}

type cPage struct{}

func (c *cPage) List(r *ghttp.Request) {
	page:=r.Get("page").Int()
	limit:=r.Get("limit").Int()
	sort := r.Get("sort").String()
	domain:=r.Get("domain").String()
	action:=r.Get("action").String()
	uri:=r.Get("uri").String()
	if sort== "+create_time"{
		sort="create_time asc"
	}else if sort== "-create_time"{
		sort="create_time desc"
	}else if sort== "+update_time"{
		sort="update_time asc"
	}else if sort== "-update_time"{
		sort="update_time desc"
	}else{
		sort="create_time desc"
	}


	SearchList := g.Map{}
	if  domain !=  "" {
		SearchList["domain"]=domain
	}
	if  action !=  "" {
		SearchList["action"]=action
	}
	if  uri !=  "" {
		SearchList["uri"]=uri
	}
	PageResult,err := dao.Page.DB().Model("page").Page(page,limit).Where(SearchList).Order(sort).All()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	TotalCount,err := dao.Page.DB().Model("page").Count()
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
			"total":TotalCount,
			"items":PageResult.List(),
		},
	})

}

func (c *cPage) Create(r *ghttp.Request) {
	action:=r.Get("action").String()
	domain:=r.Get("domain").String()
	method:=r.Get("method").String()
	uri:=r.Get("uri").String()
	add_reason:=r.Get("add_reason").String()

	//必填项校验
	if domain=="" || method == "" || action == ""  || uri == ""{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}


	ListMap := g.Map{
		"add_reason":add_reason,
		"action":action,
		"domain":domain,
		"uri":uri,
		"method":method,
		"create_time":gtime.Datetime(),
		"update_time":gtime.Datetime(),
	}
	PageId,err  :=   dao.Page.DB().Model("page").InsertAndGetId(ListMap)
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
			"id":PageId,
		},
	})

}

func (c *cPage) Update(r *ghttp.Request) {
	action:=r.Get("action").String()
	domain:=r.Get("domain").String()
	method:=r.Get("method").String()
	uri:=r.Get("uri").String()
	add_reason:=r.Get("add_reason").String()
	id:=r.Get("id").Int()

	//必填项校验
	if id == 0 || domain=="" || method == "" || action == ""  || uri == ""{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	SearchMap := g.Map{
		"id":id,
	}

	ListMap := g.Map{
		"add_reason":add_reason,
		"action":action,
		"domain":domain,
		"uri":uri,
		"method":method,
		"update_time":gtime.Datetime(),
	}
	PageId,err  :=   dao.Page.DB().Model("page").Where(SearchMap).Update(ListMap)
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
			"id":PageId,
		},
	})

}

func (c *cPage) Delete(r *ghttp.Request) {
	id := r.Get("id").Int()
	//必填项校验
	if  id == 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "id为空",
			"data": "",
		})
	}
	SearchList := g.Map{
		"id":id,
	}
	//查找是否有该id的项目
	Count,err := dao.Page.DB().Model("page").Where(SearchList).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if Count == 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "未找到该项目",
			"data": "",
		})
	}

	//删除应用
	Result,err := dao.Page.DB().Model("page").Where(SearchList).Delete()
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
			"id":Result,
		},
	})

}