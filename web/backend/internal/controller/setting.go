package controller

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"waf/internal/dao"
)

var Setting = cSetting{}

type cSetting struct{}

func (c *cSetting) List(r *ghttp.Request) {
	VulnResult, err := dao.Vuln.DB().Model("vuln").All()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//查找全局开关列表
	ModuleSwitchResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "ModuleSwitch"}).All()
	ModuleSwitchMap := ModuleSwitchResult.MapKeyValue("key")
	ModuleSwitchMapResult := g.Map{}
	for k, v := range ModuleSwitchMap {
		ModuleSwitchMapResult[k] = v.Map()["value"]

	}
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//查找鉴权配置列表
	ApiAuthResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "ApiAuth"}).All()
	ApiAuthMap := ApiAuthResult.MapKeyValue("key")
	ApiAuthMapResult := g.Map{}
	for k, v := range ApiAuthMap {
		ApiAuthMapResult[k] = v.Map()["value"]

	}
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//查找联动封禁配置列表
	RchainResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "Rchain"}).All()
	RchainMap := RchainResult.MapKeyValue("key")
	RchainMapResult := g.Map{}
	for k, v := range RchainMap {
		RchainMapResult[k] = v.Map()["value"]

	}
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
			"vuln":         VulnResult.List(),
			"ModuleSwitch": ModuleSwitchMapResult,
			"ApiAuth":      ApiAuthMapResult,
			"Rchain":       RchainMapResult,
		},
	})

}

func (c *cSetting) BaseList(r *ghttp.Request) {
	//查找CDN设置
	CdnResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "Cdn"}).All()
	CdnhMap := CdnResult.MapKeyValue("key")
	CdnhMapResult := g.Map{}
	for k, v := range CdnhMap {
		CdnhMapResult[k] = v.Map()["value"]

	}
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//查找拦截设置
	DenyMsgResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "DenyMsg"}).All()
	DenyMsgMap := DenyMsgResult.MapKeyValue("key")
	DenyMsgMapResult := g.Map{}
	for k, v := range DenyMsgMap {
		DenyMsgMapResult[k] = v.Map()["value"]

	}
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//查找日志配置
	LogResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "Log"}).All()
	LogMap := LogResult.MapKeyValue("key")
	LogMapResult := g.Map{}
	for k, v := range LogMap {
		LogMapResult[k] = v.Map()["value"]

	}
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//查找ES配置
	EsResult, err := dao.Vuln.DB().Model("setting").Where(g.Map{"group": "Es"}).All()
	EsMap := EsResult.MapKeyValue("key")
	EsMapResult := g.Map{}
	for k, v := range EsMap {
		EsMapResult[k] = v.Map()["value"]

	}
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
			"Cdn":     CdnhMapResult,
			"DenyMsg": DenyMsgMapResult,
			"Log":     LogMapResult,
			"Es":      EsMapResult,
		},
	})

}

func (c *cSetting) CreateVuln(r *ghttp.Request) {
	name := r.Get("name").String()
	key := r.Get("key").String()
	if name == "" || key == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	//检查是否重复
	SearchMap := g.Map{
		"key": key,
	}
	isempty, err := dao.Vuln.DB().Model("vuln").Where(SearchMap).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if isempty > 0 {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "关键词已经存在，不要重复添加",
			"data": "",
		})
	}
	ListMap := g.Map{}
	ListMap["name"] = name
	ListMap["key"] = key
	ListMap["create_time"] = gtime.Datetime()
	ListMap["update_time"] = gtime.Datetime()
	id, err := dao.Vuln.DB().Model("vuln").InsertAndGetId(ListMap)
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"data": g.Map{"id": id},
	})
}

func (c *cSetting) UpdateVuln(r *ghttp.Request) {
	id := r.Get("id").Int()
	name := r.Get("name").String()
	key := r.Get("key").String()
	if id == 0 || name == "" || key == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	//检查是否重复
	SearchMap := g.Map{
		"id": id,
	}
	isempty, err := dao.Vuln.DB().Model("vuln").Where(SearchMap).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}

	if isempty == 0 {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "没有找到该项目",
			"data": "",
		})
	}
	ListMap := g.Map{}
	ListMap["name"] = name
	ListMap["key"] = key
	ListMap["update_time"] = gtime.Datetime()
	idu, err := dao.Vuln.DB().Model("vuln").Where(SearchMap).Update(ListMap)
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"data": g.Map{"id": idu},
	})
}

func (c *cSetting) DeleteVuln(r *ghttp.Request) {
	id := r.Get("id").Int()
	if id == 0 {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "ID不能为空",
			"data": "",
		})
	}
	//检查是否存在
	SearchMap := g.Map{
		"id": id,
	}
	isempty, err := dao.Vuln.DB().Model("vuln").Where(SearchMap).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if isempty == 0 {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "没有找到该项目ID",
			"data": "",
		})
	}

	idu, err := dao.Vuln.DB().Model("vuln").Where(SearchMap).Delete()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"data": g.Map{"id": idu},
	})
}

func (c *cSetting) SaveModuleSwitch(r *ghttp.Request) {
	all := r.Get("all").String()
	ip := r.Get("ip").String()
	page := r.Get("page").String()
	rate := r.Get("rate").String()
	rule := r.Get("rule").String()
	if all == "" || page == "" || rate == "" || ip == "" || rule == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}

	ListMap := g.List{
		{"group": "ModuleSwitch", "key": "all", "value": all},
		{"group": "ModuleSwitch", "key": "ip", "value": ip},
		{"group": "ModuleSwitch", "key": "page", "value": page},
		{"group": "ModuleSwitch", "key": "rate", "value": rate},
		{"group": "ModuleSwitch", "key": "rule", "value": rule},
	}
	UpdateWithInsertList(ListMap, r)

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

func (c *cSetting) SaveApiAuth(r *ghttp.Request) {
	status := r.Get("status").String()
	token := r.Get("token").String()
	if status == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "状态不能为空",
			"data": "",
		})
	}
	if status == "on" && token == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "开启鉴权，token不能为空",
			"data": "",
		})
	}

	ListMap := g.List{
		{"group": "ApiAuth", "key": "status", "value": status},
		{"group": "ApiAuth", "key": "token", "value": token},
	}
	UpdateWithInsertList(ListMap, r)

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

func (c *cSetting) SaveRchain(r *ghttp.Request) {
	status := r.Get("status").String()
	attack_time := r.Get("attack_time").Int()
	attack_count := r.Get("attack_count").Int()
	action_time := r.Get("action_time").Int()
	action_method := r.Get("action_method").String()
	if status == "" || attack_time == 0 || attack_count == 0 || action_time == 0 || action_method == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}

	ListMap := g.List{
		{"group": "Rchain", "key": "status", "value": status},
		{"group": "Rchain", "key": "attack_time", "value": attack_time},
		{"group": "Rchain", "key": "attack_count", "value": attack_count},
		{"group": "Rchain", "key": "action_time", "value": action_time},
		{"group": "Rchain", "key": "action_method", "value": action_method},
	}
	UpdateWithInsertList(ListMap, r)

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

func (c *cSetting) SaveCdn(r *ghttp.Request) {
	status := r.Get("status").String()
	header_name := r.Get("header_name").String()
	token_left := r.Get("token_left").String()
	token_right := r.Get("token_right").String()
	if status == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	ListMap := g.List{
		{"group": "Cdn", "key": "status", "value": status},
		{"group": "Cdn", "key": "header_name", "value": header_name},
		{"group": "Cdn", "key": "token_left", "value": token_left},
		{"group": "Cdn", "key": "token_right", "value": token_right},
	}
	UpdateWithInsertList(ListMap, r)
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

func (c *cSetting) SaveDenyMsg(r *ghttp.Request) {
	status := r.Get("status").String()
	http_code := r.Get("http_code").String()
	msg := r.Get("msg").String()

	if status == "" || http_code == "" || msg == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}

	ListMap := g.List{
		{"group": "DenyMsg", "key": "status", "value": status},
		{"group": "DenyMsg", "key": "http_code", "value": http_code},
		{"group": "DenyMsg", "key": "msg", "value": msg},
	}
	UpdateWithInsertList(ListMap, r)

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

func (c *cSetting) SaveLog(r *ghttp.Request) {
	status := r.Get("status").String()
	dir := r.Get("dir").String()
	filename := r.Get("filename").String()

	if status == "" || dir == "" || filename == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	ListMap := g.List{
		{"group": "Log", "key": "status", "value": status},
		{"group": "Log", "key": "dir", "value": dir},
		{"group": "Log", "key": "filename", "value": filename},
	}
	UpdateWithInsertList(ListMap, r)
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

func (c *cSetting) SaveEs(r *ghttp.Request) {
	api := r.Get("api").String()
	username := r.Get("username").String()
	password := r.Get("password").String()
	index := r.Get("index").String()
	if api == "" {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}
	ListMap := g.List{
		{"group": "Es", "key": "api", "value": api},
		{"group": "Es", "key": "username", "value": username},
		{"group": "Es", "key": "password", "value": password},
		{"group": "Es", "key": "index", "value": index},
	}
	UpdateWithInsertList(ListMap, r)
	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{"success": "true"},
	})
}

//不存在配置项则新增，如果存在配置则更新。
func UpdateWithInsertList(SettingList g.List, r *ghttp.Request) {
	for _, v := range SettingList {
		SearchMap := g.Map{
			"group": v["group"],
			"key":   v["key"],
		}
		ListMap := v
		UpdateWithInsert(SearchMap, ListMap, r)
	}
}

//不存在配置项则新增，如果存在配置则更新。
func UpdateWithInsert(SearchMap g.Map, ListMap g.Map, r *ghttp.Request) {
	SearchCount, err := dao.Setting.DB().Model("setting").Where(SearchMap).Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	if SearchCount > 0 {
		dao.Setting.DB().Model("setting").Where(SearchMap).Update(ListMap)
	} else {
		dao.Setting.DB().Model("setting").Insert(ListMap)
	}
}
