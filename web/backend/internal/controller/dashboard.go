package controller

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/olivere/elastic/v7"
	"time"
	"waf/internal/dao"
)

var Dashboard = cDashboard{}

type cDashboard struct{}

func (c *cDashboard) List(r *ghttp.Request) {
	//计算搭载规则数量
	RuleCount ,err := dao.Rule.DB().Model("rule").
		Where("status != ?","off").Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//计算应用数量
	AppCount ,err := dao.App.DB().Model("app").Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//计算IP黑名单数量
	IpDenyCount ,err := dao.Ip.DB().Model("ip").Where("action = ","deny").Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	//计算IP白名单数量
	IpAllowCount ,err := dao.Ip.DB().Model("ip").Where("action = ","allow").Count()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"msg":  err.Error(),
			"data": "",
		})
	}
	r.Response.WriteJson(g.Map{
		"code": 200,
		"data":g.Map{
			"IpAllowCount":IpAllowCount,
			"IpDenyCount":IpDenyCount,
			"AppCount":AppCount,
			"RuleCount":RuleCount,
		},
	})
}

func (c *cDashboard) Line(r *ghttp.Request) {

	SearchDate := r.Get("SearchDate").Int()
	if SearchDate == 0 {
		SearchDate = 7
	}
	PickTime := r.Get("PickTime").Array()

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
	m, _ := time.ParseDuration(fmt.Sprintf("-%dh",SearchDate*24))
	gte_time := lte_time.Add(m)

	if len(PickTime) > 1 {
		lte_time_to = gconv.Int64(PickTime[1])
		gte_time_from = gconv.Int64(PickTime[0])

	}else{
		lte_time_to = lte_time.UnixNano() / 1e6
		gte_time_from = gte_time.UnixNano() / 1e6
	}
	//生成X坐标轴
	ResultAggDate :=  Get_Time(gte_time_from,lte_time_to)

	ctx := context.Background()
	defer ctx.Done()
	termQuery := elastic.NewTermsQuery("factory","easywaf")
	boolQuery := elastic.NewBoolQuery()
	boolQuery.Must(termQuery)


	timeRangeFilter := elastic.NewRangeQuery("time").Gte(gte_time_from).Lte(lte_time_to)

	// 创DateHistogram桶聚合
	aggs := elastic.NewDateHistogramAggregation().
	Field("@timestamp"). // 根据date字段值，对数据进行分组
	//  分组间隔：month代表每月、支持minute（每分钟）、hour（每小时）、day（每天）、week（每周）、year（每年)
	CalendarInterval("day").
	// 设置返回结果中桶key的时间格式
	Format("yyyy-MM-dd")
	boolQuery.Must(timeRangeFilter)
	searchResult, err := client.Search().
		Index(api_index). // 设置索引名
		Query(boolQuery). // 设置查询条件
		Aggregation("sales_over_time", aggs). // 设置聚合条件，并为聚合条件设置一个名字
		Size(0). // 设置分页参数 - 每页大小,设置为0代表不返回搜索结果，仅返回聚合分析结果
		Do(ctx) // 执行请求

	client.Stop()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"data":"",
			"msg":err.Error(),
		})
	}
	AggData,_ :=searchResult.Aggregations.Filter("sales_over_time")


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
	//host字段聚合查询
	AggsHost := elastic.NewTermsAggregation().
		Field("host.keyword")
	boolQuery.Must(timeRangeFilter)
	HostSearchResult, err := client.Search().
		Index(api_index). // 设置索引名
		Query(boolQuery). // 设置查询条件
		Aggregation("host", AggsHost). // 设置聚合条件，并为聚合条件设置一个名字
		Size(0). // 设置分页参数 - 每页大小,设置为0代表不返回搜索结果，仅返回聚合分析结果
		Do(ctx) // 执行请求
	client.Stop()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"data":"",
			"msg":err.Error(),
		})
	}
	HostAggData,_ :=HostSearchResult.Aggregations.Filter("host")

	//real_ip 字段聚合查询
	AggsIp := elastic.NewTermsAggregation().
		Field("real_ip.keyword")
	boolQuery.Must(timeRangeFilter)
	IpSearchResult, err := client.Search().
		Index(api_index). // 设置索引名
		Query(boolQuery). // 设置查询条件
		Aggregation("ip", AggsIp). // 设置聚合条件，并为聚合条件设置一个名字
		Size(0). // 设置分页参数 - 每页大小,设置为0代表不返回搜索结果，仅返回聚合分析结果
		Do(ctx) // 执行请求
	client.Stop()
	if err != nil {
		r.Response.WriteJsonExit(g.Map{
			"code": 400,
			"data":"",
			"msg":err.Error(),
		})
	}
	IpAggData,_ :=IpSearchResult.Aggregations.Filter("ip")

	r.Response.WriteJson(g.Map{
		"code": 200,
		"data":g.Map{
			"total":searchResult.TotalHits(),
			"items":AggData,
			"ResultAggDate":ResultAggDate,
			"ResultHost":HostAggData,
			"ResultIp":IpAggData,

		},
	})


}

func Get_Time(start_time, stop_time int64) (args []string) {
	tm1, _ := time.Parse("2006-01-02", gtime.NewFromTimeStamp(start_time).Format("Y-m-d"))
	tm2, _ := time.Parse("2006-01-02", gtime.NewFromTimeStamp(stop_time).Format("Y-m-d"))
	sInt := tm1.Unix()
	eInt := tm2.Unix()
	for {
		sInt += 86400
		st := time.Unix(sInt, 0).Format("2006-01-02")
		if sInt > eInt {
			return
		}
		args = append(args,st)

	}
}

