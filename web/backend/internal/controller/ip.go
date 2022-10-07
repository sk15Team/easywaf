package controller

import (
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gregex"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
	"strings"
	"waf/internal/dao"
)

var Ip = cIp{}

type cIp struct{}

func (c *cIp) List(r *ghttp.Request) {
	page:=r.Get("page").Int()
	limit:=r.Get("limit").Int()
	sort := r.Get("sort").String()
	ip:=r.Get("ip").String()
	action:=r.Get("action").String()
	sort="create_time desc"


	SearchList := g.Map{}
	if  ip !=  "" {
		SearchList["ip"]=ip
	}
	if  action !=  "" {
		SearchList["action"]=action
	}
	IpResult,err := dao.Ip.DB().Model("ip").Page(page,limit).Where(SearchList).Order(sort).All()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	TotalCount,err := dao.Ip.DB().Model("ip").Count()
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
			"items":IpResult.List(),
		},
	})

}

func (c *cIp) Create(r *ghttp.Request) {
	ip := r.Get("ip").String()
	action:=r.Get("action").String()
	domain:=r.Get("domain").String()
	otherdomain:=r.Get("otherdomain").String()
	expire_time:=r.Get("expire_time").Int()
	add_reason:=r.Get("add_reason").String()

	//必填项校验
	if domain=="" || ip == "" || action == ""  {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  "有必填项为空",
			"data": "",
		})
	}


	ListMap := g.Map{
		"add_reason":add_reason,
		"action":action,
		"ip":ip,
		"create_time":gtime.Datetime(),
	}
	//处理作用域
	if  domain == "other"{
		ListMap["domain"] = otherdomain
	}else{
		ListMap["domain"] = "default"
	}
	//处理作用时间
	if expire_time == 0 {
		ListMap["expire_time"] = 0
	}else{
		ListMap["expire_time"] = gtime.Timestamp() + gconv.Int64(expire_time)
	}
	//处理IP列表
	if strings.Contains(ip,"\n") == true{
		IpList := gstr.SplitAndTrim(ip,"\n")
		for _,v := range IpList{
			if CheckIp(v) == false{
				r.Response.WriteJsonExit(g.Map{
					"code": 400,
					"msg": "错误的IP格式",
					"data": "",
				})
			}

		}
		for _,v := range IpList{
			AddStatus ,ErrReason  :=  AddIp(v,ListMap)
			if AddStatus == false{
				r.Response.WriteJsonExit(g.Map{
					"code": 400,
					"msg":  fmt.Sprintf("IP:%s保存失败，%s",v,ErrReason),
					"data": "",
				})
			}
		}

	}else{
		if CheckIp(ip) == false{
			r.Response.WriteJsonExit(g.Map{
				"code": 400,
				"msg": "错误的IP格式",
				"data": "",
			})
		}
		AddStatus ,ErrReason  :=  AddIp(ip,ListMap)
		if AddStatus == false{
			r.Response.WriteJsonExit(g.Map{
				"code": 400,
				"msg":  fmt.Sprintf("IP:%s保存失败，%s",ip,ErrReason),
				"data": "",
			})
		}
	}

	r.Response.WriteJson(g.Map{
		"code": 200,
		"msg":  "",
		"data": g.Map{
			"success":true,
		},
	})

}

//检查IP是否符合IPV4规则
func CheckIp(ip string) bool {
	PatternCIDR := "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\/([1-9]|[1-2]\\d|3[0-2])$"
	PatternIPV4 := "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"
	if gregex.IsMatch(PatternCIDR, []byte(ip))  || gregex.IsMatch(PatternIPV4, []byte(ip)) {
		return true
	}else{
		return false
	}


}
func AddIp(ip string,ListMap g.Map) (bool,string){
	//判断IP是否为空。后端没有校验IP格式是否正确，需要用户自行确认。WAF节点也会对IP格式进行再次确认校验。
	if ip == ""{
		return false ,"IP地址不能为空"
	}

	//判断同IP 同域名下是否已经存在记录
	SearchMap := g.Map{
		"ip":ip,
		"domain":ListMap["domain"],
	}
	IpCount,err := dao.Ip.DB().Model("ip").Where(SearchMap).Count()
	if err != nil {
		return false ,err.Error()
	}
	if IpCount > 0  {
		return false ,"同域名下，不允许重复添加IP"
	}
	ListMap["ip"] = ip
	//添加IP
	dao.Ip.DB().Model("ip").Insert(ListMap)
	return true,""
}



func (c *cIp) Delete(r *ghttp.Request) {
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
	Count,err := dao.Ip.DB().Model("ip").Where(SearchList).Count()
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
	IpResult,err := dao.Ip.DB().Model("ip").Where(SearchList).Delete()
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
			"id":IpResult,
		},
	})

}