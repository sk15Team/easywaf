package controller

import (
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
	"waf/internal/dao"
)

var App = cApp{}

type cApp struct{}

func (c *cApp) List(r *ghttp.Request) {
	page:=r.Get("page").Int()
	limit:=r.Get("limit").Int()
	sort := r.Get("sort").String()
	domain:=r.Get("domain").String()
	appmaintainer:=r.Get("appmaintainer").String()
	state:=r.Get("state").String()
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
		SearchList["domain like ?"]=fmt.Sprintf("%%%s%%",domain)
	}
	if  appmaintainer !=  "" {
		SearchList["appmaintainer like ?"]=fmt.Sprintf("%%%s%%",appmaintainer)
	}
	if  state !=  "" {
		SearchList["state"]=state
	}
	AppResult,err := dao.App.DB().Model("app").Page(page,limit).Where(SearchList).Order(sort).All()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	TotalCount,err := dao.App.DB().Model("app").Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//生成规则分类树
	VulnResult,err := dao.Vuln.DB().Model("vuln").Fields("id,`key`,name as label").All()
	VulnTree := VulnResult.List()
	for _,v :=range VulnTree{

		SearchListR := g.Map{
			"vuln":v["key"],
		}


		RuleResult,err := dao.Rule.DB().Model("rule").Fields("ruleid,name as label").Where(SearchListR).All()
		if err == nil {
			v["children"] = RuleResult.List()
		}
		v["label"]=gconv.String(v["label"]) + fmt.Sprintf("[%d]",len(RuleResult))
	}
	//搜索未分类的规则
	RuleResultN,err := dao.Rule.DB().Model("rule").Fields("ruleid,name as label").Where("vuln = '' ").All()
	VulnTree=append(VulnTree, g.Map{
		"label":fmt.Sprintf("未分类[%d]",len(RuleResultN)),
		"children":RuleResultN.List(),
	})
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{
			"total":TotalCount,
			"items":AppResult.List(),
			"rule":VulnTree,
		},
	})

}

func (c *cApp) Create(r *ghttp.Request) {
	domain := r.Get("domain").String()
	appname:=r.Get("appname").String()
	appmaintainer:=r.Get("appmaintainer").String()
	state:=r.Get("state").String()
	ratelimit:=r.Get("ratelimit").String()
	lmtime:=r.Get("lmtime").String()
	lmcount:=r.Get("lmcount").String()
	description:=r.Get("description").String()
	rule:=r.Get("rule").Array()
	//必填项校验
	if domain=="" || appmaintainer == "" || state == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	SearchList := g.Map{
		"domain":domain,
	}

	AppCount,err := dao.App.DB().Model("app").Where(SearchList).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if AppCount > 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "已经存在该域名，不要重复添加",
			"data": "",
		})
	}
	ListMap := g.Map{
		"domain":domain,
		"appname":appname,
		"appmaintainer":appmaintainer,
		"state":state,
		"ratelimit":ratelimit,
		"lmtime":lmtime,
		"lmcount":lmcount,
		"description":description,
		"rule":rule,
		"create_time":gtime.Datetime(),
		"update_time":gtime.Datetime(),
	}
	//新增应用
	AppResultId,err := dao.App.DB().Model("app").InsertAndGetId(ListMap)
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
			"id":AppResultId,
		},
	})

}

func (c *cApp) Update(r *ghttp.Request) {
	id := r.Get("id").Int()
	domain := r.Get("domain").String()
	appname:=r.Get("appname").String()
	appmaintainer:=r.Get("appmaintainer").String()
	state:=r.Get("state").String()
	ratelimit:=r.Get("ratelimit").String()
	lmtime:=r.Get("lmtime").String()
	lmcount:=r.Get("lmcount").String()
	description:=r.Get("description").String()
	rule:=r.Get("rule").Array()
	//必填项校验
	if domain=="" || appmaintainer == "" || state == "" || id == 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	SearchList := g.Map{
		"id":id,
	}
	//查找是否有该id的项目
	AppCount,err := dao.App.DB().Model("app").Where(SearchList).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if AppCount == 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "未找到该项目",
			"data": "",
		})
	}
	//修改的domain是否重复
	AppCountD,err := dao.App.DB().Model("app").Where("`domain` = ? and `id` != ?",domain,id).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if AppCountD > 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "域名重复",
			"data": "",
		})
	}

	ListMap := g.Map{
		"domain":domain,
		"appname":appname,
		"appmaintainer":appmaintainer,
		"state":state,
		"ratelimit":ratelimit,
		"lmtime":lmtime,
		"lmcount":lmcount,
		"description":description,
		"rule":rule,
		"update_time":gtime.Datetime(),
	}
	//新增应用
	AppResult,err := dao.App.DB().Model("app").Where(SearchList).Update(ListMap)
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
			"id":AppResult,
		},
	})

}

func (c *cApp) Delete(r *ghttp.Request) {
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
	AppCount,err := dao.App.DB().Model("app").Where(SearchList).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if AppCount == 0{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "未找到该项目",
			"data": "",
		})
	}

	//删除应用
	AppResult,err := dao.App.DB().Model("app").Where(SearchList).Delete()
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
			"id":AppResult,
		},
	})

}