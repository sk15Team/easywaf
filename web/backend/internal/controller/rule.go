package controller

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/google/uuid"
	"waf/internal/dao"
)

var Rule = cRule{}

type cRule struct{}

func (c *cRule) List(r *ghttp.Request) {
	page:=r.Get("page").Int()
	limit:=r.Get("limit").Int()
	sort := r.Get("sort").String()
	ruleid:=r.Get("ruleid").String()
	name:=r.Get("name").String()
	key:=r.Get("key").String()
	vuln:=r.Get("vuln").String()
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
	if  ruleid !=  "" {
		SearchList["ruleid"]=ruleid
	}
	if  name !=  "" {
		SearchList["name"]=name
	}
	if  key !=  "" {
		SearchList["key"]=key
	}
	if  vuln !=  "" {
		SearchList["vuln"]=vuln
	}
	RuleResult,err := dao.Rule.DB().Model("rule").Page(page,limit).Where(SearchList).Order(sort).All()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	TotalCount,err := dao.Rule.DB().Model("rule").Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//搜索规则分类
	VulnResult,err := dao.Rule.DB().Model("vuln").All()
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{
			"total":TotalCount,
			"items":RuleResult.List(),
			"vuln":VulnResult,
		},
	})

}

func (c *cRule) Create(r *ghttp.Request)  {
	name := r.Get("name").String()
	action := r.Get("action").String()
	ct := r.Get("ct").String()
	key := r.Get("key").String()
	level := r.Get("level").String()
	rule_content := r.Get("rule_content").String()
	status := r.Get("status").String()
	vuln := r.Get("vuln").String()
	//必填项校验
	if name=="" || key == "" || action == "" ||  rule_content == "" || status ==   "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	//生成uuid
	uuid := uuid.New()
	ruleid := uuid.String()
	create_time:=gtime.Datetime()
	update_time:=gtime.Datetime()
	//插入数据
	ListMap := g.Map{
		"name":name,
		"action":action,
		"ct":ct,
		"key":key,
		"level":level,
		"rule_content":rule_content,
		"ruleid":ruleid,
		"status":status,
		"vuln":vuln,
		"create_time":create_time,
		"update_time":update_time,
	}
	_,err :=dao.Rule.DB().Model("rule").InsertAndGetId(ListMap)
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":"",
		"data": g.Map{},
	})
}

func (c *cRule) Update(r *ghttp.Request)  {
	name := r.Get("name").String()
	action := r.Get("action").String()
	ct := r.Get("ct").String()
	key := r.Get("key").String()
	level := r.Get("level").String()
	rule_content := r.Get("rule_content").String()
	status := r.Get("status").String()
	vuln := r.Get("vuln").String()
	ruleid := r.Get("ruleid").String()
	//必填项校验
	if name=="" || key == "" || action == "" ||  rule_content == "" || status ==   "" || ruleid == ""{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	update_time:=gtime.Datetime()
	SearchMap := g.Map{
		"ruleid":ruleid,
	}
	SearchCount,err := dao.Rule.DB().Model("rule").Where(SearchMap).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if SearchCount < 1{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "没有找到该项目",
			"data": "",
		})
	}
	//插入数据
	ListMap := g.Map{
		"name":name,
		"action":action,
		"ct":ct,
		"key":key,
		"level":level,
		"rule_content":rule_content,
		"ruleid":ruleid,
		"status":status,
		"vuln":vuln,
		"update_time":update_time,
	}
	_,err =dao.Rule.DB().Model("rule").Where(SearchMap).Update(ListMap)
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":"",
		"data": g.Map{},
	})
}

func (c *cRule) Delete(r *ghttp.Request)  {
	ruleid := r.Get("ruleid").String()
	//必填项校验
	if  ruleid == ""{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "ruleid为空",
			"data": "",
		})
	}
	SearchMap := g.Map{
		"ruleid":ruleid,
	}
	SearchCount,err := dao.Rule.DB().Model("rule").Where(SearchMap).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if SearchCount < 1{
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "没有找到该项目",
			"data": "",
		})
	}

	_,err =dao.Rule.DB().Model("rule").Where(SearchMap).Delete()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":"",
		"data": g.Map{},
	})
}