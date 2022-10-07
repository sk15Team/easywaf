package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/os/gtimer"
	"github.com/gogf/gf/v2/text/gregex"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/olivere/elastic/v7"
	"time"
	"waf/common"
	"waf/internal/dao"
)

var RchinMap = make(map[string]*common.ExpiredMap)
var Attack_count int
var Action_method string
var Action_time int
//定义日志结构体
type LogStruct struct {
	Real_ip string
	Time int64

}

//定时任务模块
func Run() {
	var CtxIp = gctx.New()
	gtimer.Add(CtxIp,30*time.Second, CheckExpireTime)
	var CtxRchain = gctx.New()
	gtimer.Add(CtxRchain,10*time.Second, RchainBlock)
	var CtxRchainDeny = gctx.New()
	gtimer.Add(CtxRchainDeny,1*time.Second, RchainBlockDeny)
}


//删除过期的IP定时任务
func CheckExpireTime(ctx context.Context){
	//查找过期的IP控制名单，删除之
	SearchList:= g.Map{
		"expire_time < ": gtime.Timestamp(),
		"expire_time !=":0,
	}
	dao.Ip.DB().Model("ip").Where(SearchList).Delete()

}
//联动封禁功能，根据deny日志判定，加入队列
func RchainBlock(ctx context.Context)  {
	var CtxSearch = gctx.New()
	defer CtxSearch.Done()
	//获取ES配置
	SettingResult ,err := dao.Setting.DB().Model("setting").Where("group","Es").
		Fields("group,key,value").All()
	//没有ES配置直接返回
	if len(SettingResult) < 1 || err !=nil{
		return
	}

	ES := SettingResult.MapKeyStr("key")
	api_address  := gconv.String(ES["api"]["value"])
	api_username := gconv.String(ES["username"]["value"])
	api_password := gconv.String(ES["password"]["value"])
	api_index := gconv.String(ES["index"]["value"])

	//获取联动封禁配置
	SettingRchainResult ,err := dao.Setting.DB().Model("setting").Where("group","Rchain").
		Fields("group,key,value").All()
	if len(SettingRchainResult) < 1 || err !=nil {
		return
	}
	Rchain := SettingRchainResult.MapKeyStr("key")
	attack_time  := gconv.String(Rchain["attack_time"]["value"])
	Attack_count = gconv.Int(Rchain["attack_count"]["value"])
	Action_method = gconv.String(Rchain["action_method"]["value"])
	Action_time = gconv.Int(Rchain["action_time"]["value"])
	//建立ES链接
	client, err := elastic.NewClient(elastic.SetSniff(false),elastic.SetURL(api_address),
		elastic.SetBasicAuth(api_username,api_password))
	if err != nil {
		return
	}
	defer client.Stop()
	//查询ES日志

	termQuery := elastic.NewTermsQuery("factory","easywaf")

	boolQuery := elastic.NewBoolQuery()
	boolQuery.Must(termQuery)


	termQueryAction := elastic.NewMatchPhraseQuery("action","deny")
	boolQuery.Must(termQueryAction)

	var lte_time_to , gte_time_from int64
	lte_time := time.Now()
	m, _ := time.ParseDuration(fmt.Sprintf("-%ds",gconv.Int(attack_time)))
	gte_time := lte_time.Add(m)
	lte_time_to = lte_time.UnixNano() / 1e6
	gte_time_from = gte_time.UnixNano() / 1e6

	timeRangeFilter := elastic.NewRangeQuery("time").Gte(gte_time_from).Lte(lte_time_to)


	boolQuery.Must(timeRangeFilter)
	searchResult, err := client.Search().
		Index(api_index).
		Query(boolQuery).   // specify the query
		Sort("time", false).
		Size(10000).
		Pretty(true).       // pretty print request and response JSON
		Do(CtxSearch)             // execute
	if err != nil {
		g.Log().Info(CtxSearch,"ES搜索失败：",err.Error())
		return
	}
	for _, hit := range searchResult.Hits.Hits {

		var ttyp LogStruct
		err := json.Unmarshal(hit.Source, &ttyp)
		if err != nil {
			return
		}
		doc_id := hit.Id
		doc_timestamp := ttyp.Time
		doc_real_ip :=   ttyp.Real_ip

		attack_time_expired :=gconv.Int64(attack_time) - (gtime.TimestampMilli() - doc_timestamp)/1000
		if RchinMap[doc_real_ip]  == nil{
			cache := common.NewExpiredMap()
			if CheckIpDeny(doc_real_ip) == true{
				return
			}
			cache.Set(doc_id,doc_timestamp,attack_time_expired)
			RchinMap[doc_real_ip] = cache
		}else{
			ca := RchinMap[doc_real_ip]
			Found , _ :=ca.Get(doc_id)
			if  Found != true{
				if CheckIpDeny(doc_real_ip) == true{
					return
				}
				ca.Set(doc_id,doc_timestamp,attack_time_expired)
			}
		}


	}


}

//判断IP是否在IP控制列表内，已存在的IP不加入队列，不进行封禁
func CheckIpDeny(ip string)bool{
	//IP 是否为内网IP
	PatternIP:= "^(127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(localhost)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3})$"
	if gregex.IsMatch(PatternIP, []byte(ip)){
		return true
	}
	IpCOunt,err :=dao.Ip.DB().Model("ip").Where("ip = ?",ip).Count()
	if err != nil {
		return true
	}
	if IpCOunt > 0{
		return true
	}else{
		return false
	}
}
//将IP加入列表封禁
func IpDeny(ip string)  {
	if Action_method  == "" ||  Action_time ==0{
		return
	}
	ListMap := g.Map{
		"add_reason":"WAF日志聚合封禁",
		"action":Action_method,
		"ip":ip,
		"domain":"default",
		"create_time":gtime.Datetime(),
	}
	ListMap["expire_time"] = gtime.Timestamp() + gconv.Int64(Action_time)
	dao.Ip.DB().Model("ip").Insert(ListMap)
}
//联动封禁功能，根据队列选择出需要封禁的IP进行封禁
func RchainBlockDeny(ctx context.Context){
	//是否已取到封禁配置
	if Attack_count == 0  {
		return
	}
	for ip,cache := range RchinMap{
		//判断IP是否已经过期
		if  cache.Size() ==  0{
			delete(RchinMap,ip)
		}
		//判断IP封禁
		if cache.Size() >=  Attack_count && CheckIpDeny(ip)== false  {
			//将IP加入封禁列表
			IpDeny(ip)
			delete(RchinMap,ip)
			g.Log().Info(context.Background(),fmt.Sprintf("WAF日志聚合封禁IP：%s",ip))
		}
	}
}