# dkk-waf
某训练营的大作业，基于OpenResty的web应用防火墙。

## 功能列表：
1. 支持IP白名单和黑名单
2. 通过Cookie和Token绑定，禁止越权
3. 支持指定Cookie和api接口绑定，达到鉴权
4. 支持User-Agent的过滤，匹配自定义规则中的条目，返回403
5. 支持Cookie过滤，匹配自定义规则中的条目，返回403
6. 支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403
7. 支持CC攻击防护，单个URL指定时间的访问次数，超过设定值，返回403
8. 支持日志记录，将所有拒绝的操作，记录到日志中去
9. 日志记录为JSON格式，便于日志分析，（后期可使用ELK进行攻击日志收集
## 推荐安装
推荐直接安装OpenResty部署

http://openresty.org/en/installation.html

### Ubuntu安装OpenResty

```bash
sudo apt-get -y install --no-install-recommends wget gnupg ca-certificates
wget -O - https://openresty.org/package/pubkey.gpg | sudo apt-key add -
echo "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" \
    | sudo tee /etc/apt/sources.list.d/openresty.list
sudo apt-get update
sudo apt-get -y install openresty
```

默认均安装在/usr/local/openresty目录

## WAF部署

`git clone https://github.com/eggdkk/dkk-waf /var/`

修改`/usr/local/openresty/nginx/conf/nginx.conf` 增加第一个配置

```nginx
http{
    **********

    lua_package_path "/var/dkk-waf/?.lua";
    lua_shared_dict limit 10m;
    access_by_lua_file /var/dkk-waf/auth.lua;
    log_by_lua_file /var/dkk-waf/auth_get.lua;
    *********
}
```

openresty -t    //检查nginx.conf配置文件

openresty -s reload         //修改配置后重新加载生效

openresty -s reopen         //重新打开日志文件

## 配置规则文件

默认规则文件在`/usr/local/openresty/nginx/conf/wafconfig/`,修改在`config.lua`里

规则文件均为一行一个正则表达式