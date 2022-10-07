package controller

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/olivere/elastic/v7"
	"time"
	"waf/internal/dao"
)

var Log = cLog{}

type cLog struct{}

func (c *cLog) List(r *ghttp.Request) {
	page := r.Get("page", 1).Int()
	limit := r.Get("limit", 20).Int()
	sort := r.Get("sort").String()
	AttackDomain := r.Get("AttackDomain").String()
	AttackIp := r.Get("AttackIp").String()
	EventId := r.Get("EventId").String()
	Ruleid := r.Get("Rule").String()
	Action := r.Get("Action").String()

	PickTime := r.Get("PickTime").Array()
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
	//获取ES配置
	SettingResult ,_ := dao.Setting.DB().Model("setting").Where("group","Es").
		Fields("group,key,value").All()
	if len(SettingResult) < 1 {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"data":"",
			"msg":"未发现ES配置",
		})
	}
	ES := SettingResult.MapKeyStr("key")
	api_address  := gconv.String(ES["api"]["value"])
	api_username := gconv.String(ES["username"]["value"])
	api_password := gconv.String(ES["password"]["value"])
	api_index := gconv.String(ES["index"]["value"])
	//建立ES链接
	client, err := elastic.NewClient(elastic.SetSniff(false),elastic.SetURL(api_address),
		elastic.SetBasicAuth(api_username,api_password))
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"data":"",
			"msg":err.Error(),
		})
	}

	var lte_time_to , gte_time_from int64
	lte_time := time.Now()
	m, _ := time.ParseDuration("-168h")
	gte_time := lte_time.Add(m)
	if len(PickTime) > 1 {
		lte_time_to = gconv.Int64(PickTime[1])
		gte_time_from = gconv.Int64(PickTime[0])
	}else{
		lte_time_to = lte_time.UnixNano() / 1e6
		gte_time_from = gte_time.UnixNano() / 1e6
	}


	ctx := context.Background()
	defer ctx.Done()
	termQuery := elastic.NewTermsQuery("factory","easywaf")

	boolQuery := elastic.NewBoolQuery()
	boolQuery.Must(termQuery)

	if AttackDomain != ""{
		termQueryHost := elastic.NewMatchPhraseQuery("host",AttackDomain)
		boolQuery.Must(termQueryHost)
	}

	if AttackIp != ""{
		termQueryIP := elastic.NewMatchPhraseQuery("real_ip",AttackIp)
		boolQuery.Must(termQueryIP)
	}

	if EventId != ""{
		termQueryId := elastic.NewMatchPhraseQuery("event_id",EventId)
		boolQuery.Must(termQueryId)
	}
	if Ruleid != ""{
		termQueryId := elastic.NewMatchPhraseQuery("ruleid",Ruleid)
		boolQuery.Must(termQueryId)
	}
	if Action != ""{
		termQueryId := elastic.NewMatchPhraseQuery("action",Action)
		boolQuery.Must(termQueryId)
	}
	timeRangeFilter := elastic.NewRangeQuery("time").Gte(gte_time_from).Lte(lte_time_to)
	pagefrom := limit*(page-1)

	boolQuery.Must(timeRangeFilter)
	searchResult, err := client.Search().
		Index(api_index).
		Query(boolQuery).   // specify the query
		From(pagefrom).Size(limit).   // take documents 0-9
		Sort("time", false).
		Pretty(true).       // pretty print request and response JSON
		Do(ctx)             // execute
	client.Stop()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"data":"",
			"msg":err.Error(),
		})
	}



	var waflogs g.SliceAny

	for _, hit := range searchResult.Hits.Hits {

		hitobj,err:=gjson.Decode(hit.Source)
		if   err !=  nil  {
			fmt.Println(err)
			continue
		}
		HitMap:= gconv.Map(hitobj)
		waflogs = append(waflogs,HitMap)


	}
	//搜索规则列表
	RuleResult ,_ := dao.Rule.DB().Model("rule").
		Fields("ruleid,name").All()
	RuleResultMap := RuleResult.MapKeyStr("ruleid")
	//搜索规则分类
	VulnResult ,_ := dao.Vuln.DB().Model("vuln").
		Fields("key,name").All()
	VulnResultMap := VulnResult.MapKeyStr("key")

	r.Response.WriteJson(g.Map{
		"code": 200,
		"data":g.Map{"total":searchResult.TotalHits(),
			"items":waflogs,
			"rule":RuleResultMap,
			"vuln":VulnResultMap,
		},
	})


}
