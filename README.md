## 什么是 Easywaf？

Easywaf是开源的WEB应用防火墙，基于openresty开发，适用于中小型企业，可以保护WEB应用或API接口，阻断常见的web攻击。同时Easywaf提供友好的后台管控界面，支持IP、URL、Referer、User-Agent等HTTP常见字段的自定义访问规则。


**Easywaf 的功能包括：**

-   IP访问控制：对用户IP封禁或者放行。
-   页面访问控制：对用户访问的URI进行阻断或放行控制。
-   自定义访问规则：支持uri、header、ua等请求对象基于正则表达式进行规则匹配。
-   多域名个性化策略：默认流量/自定义域名的个性化规则策略。
-   高频限速：可配置的固定时间窗口内访问总量。
-   精细化配置策略：可针对拦截返回内容、日志策略、CDN策略等多个项目精细化配置。


## Easywaf 理论上支持的网关类型

> 基于lua_nginx模块开发网关，例如openresty,ingress-nginx,kong,apisix等理论上都可以使用。


## 快速开始

**在线体验**

-   后台地址：<http://waf.sk15.top:8089/>
-   用户名：admin
-   密码：easywaf  (请勿修改密码)
-   前台地址：<http://f.sk15.top:8000/>   (随便攻击)

> 如服务不可用,可能是我的VPS没钱了-。-

**快速安装**

基于docker环境安装体验：

1. 创建docker网络

```sh
docker network create waf
```

2. 运行mysql服务

```sh
docker run --net waf --name  mysql -e MYSQL_ROOT_PASSWORD=easywaf -d sk15team/wafmysql:1.0
```

> 如更改了MYSQL_ROOT_PASSWORD,需要到后台后端docker内修改相应DB配置。

3. 运行ES服务

```sh
docker run -d --name elasticsearch --net waf  -e "discovery.type=single-node" elasticsearch:7.17.6
```
> ES需要占用的内存较大，如果快速体验，无需日志功能，则可省略此服务。亦可使用已有自建的ES服务。

4. 启动后台后端服务

```sh
docker run -d --name backend --net waf sk15team/wafbackend:1.0
```

5. 启动后台前端服务

```sh
docker run -d --name frontend --net waf -p 8089:80 sk15team/waffrontend:1.0
```

6. 启动WAF节点

```sh
docker run -d --name agent --net waf -p 8000:80 -e "WAF_HOSTNAME=$(hostname)" -e "WAF_API_TOKEN=f26320c31aa756551df12480dbbe1eb8" -e "WAF_HOST=http://backend:8199" sk15team/waf:1.0
```

## 操作手册&文档

-   地址：<https://www.kancloud.cn/sk15_team/easywaf>



## 使用的项目

-   后台前端：<https://github.com/PanJiaChen/vue-element-admin>
-   后台后端API：<https://github.com/gogf/gf>
-   代理网关：<https://github.com/openresty/openresty>
-   中间件：[MySQL](https://www.mysql.com/) [ES](https://www.elastic.co/)
-   基础设施：[Docker](https://www.docker.com/)

**感谢以上开源作者**

## 性能测试 - wrk - 本机4C8G

1. 不加载WAF：
```
Running 2m test @ http://127.0.0.1:8000
  12 threads and 400 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    16.62ms    9.79ms 290.46ms   87.71%
    Req/Sec     1.23k   425.25     3.07k    70.29%
  1767067 requests in 2.00m, 2.21GB read
  Socket errors: connect 155, read 248, write 1, timeout 0
Requests/sec:  14713.88
Transfer/sec:     18.83MB
```

2. 网关加载WAF：

```
Running 2m test @ http://127.0.0.1:8000
  12 threads and 400 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    21.68ms   14.47ms 345.56ms   82.32%
    Req/Sec     0.95k   613.45     2.25k    56.93%
  1358332 requests in 2.00m, 1.70GB read
  Socket errors: connect 155, read 139, write 0, timeout 0
Requests/sec:  11312.17
Transfer/sec:     14.48MB
```

## 交流反馈

- QQ群：154900644