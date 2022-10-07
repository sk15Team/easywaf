package controller

import (
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"waf/internal/dao"
)

var Public = cPublic{}

type cPublic struct{}

//API 鉴权
func ApiToken(Token string) bool{
	SettingResult ,_ := dao.Setting.DB().Model("setting").WhereOrIn("group",g.Array{"ApiAuth"}).
		Fields("group,key,value").All()
	SettingMap := SettingResult.MapKeyStr("key")
	if SettingMap["status"] == nil  || SettingMap["token"] == nil  || SettingMap["status"]["value"] == "off"{
		return true
	}
	if SettingMap["token"]["value"] ==Token{
		return true
	}else {
		return false
	}
}
func (c *cPublic) Rule(r *ghttp.Request) {
	RequestToken := r.GetHeader("Authentication")

	if ApiToken(RequestToken) == false{
		r.Response.WriteJsonExit(g.Map{
			"errmsg":  "wrong Authentication token",
		})
	}
	//搜索应用列表
	AppResult ,_ := dao.App.DB().Model("app").
		Fields("domain,appname,state,ratelimit,lmtime,lmcount,rule").All()
	AppMap :=AppResult.MapKeyStr("domain")
	for key,apps :=  range AppMap{
		AppMap[key]["rule"] = gjson.New(apps["rule"]).Array()
	}
	//搜索IP控制列表
	IpResult ,_ := dao.Ip.DB().Model("ip").
		Fields("ip,action,domain,expire_time").All()
	mIpMap := make(map[string]g.Map)
	for _, item := range IpResult {
		if v, ok := item["domain"]; ok {
			if  mIpMap[item["ip"].String()] == nil {
				mIpMap[item["ip"].String()] = g.Map{v.String():item.Map()}
			}else{
				mIpMap[item["ip"].String()][v.String()]= item.Map()
			}

		}
	}
	//m[v.String()][item["domain"].String()]= item.Map()
	//搜索页面控制列表
	PageResult ,_ := dao.Page.DB().Model("page").
		Fields("uri,action,domain,method").All()
	m := make(map[string]g.Array)
	for _, item := range PageResult {
		if v, ok := item["domain"]; ok {
			if  m[v.String()] == nil {
				m[v.String()] = g.Array{item.Map()}
			}else{
				m[v.String()] = append(m[v.String()],item.Map())
			}

		}
	}

	//搜索规则列表
	RuleResult ,_ := dao.Rule.DB().Model("rule").
		Fields("ruleid,key,action,rule_content,ct,status,vuln").All()
	RuleMap :=RuleResult.MapKeyValue("ruleid")
	//配置列表
	mSetting := make(map[string]g.Map)
	SettingResult ,_ := dao.Setting.DB().Model("setting").WhereOrIn("group",g.Array{"DenyMsg",
		"Log","Cdn","ModuleSwitch","ApiAuth"}).
		Fields("group,key,value").All()
	for _, item := range SettingResult {
			if  mSetting[item["group"].String()] == nil {
				mSetting[item["group"].String()]= g.Map{item["key"].String():item["value"].String()}
			}else {
				mSetting[item["group"].String()][item["key"].String()] = item["value"].String()
			}
	}
	r.Response.WriteJson(g.Map{
			"config":mSetting,
			"app":AppMap,
			"ip":mIpMap,
			"page":m,
			"rule":RuleMap,
		},
	)

}

