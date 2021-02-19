log_path = "/usr/local/openresty/nginx/logs/hack/";     -- 日志目录
filename = log_path .. "redis.log";                     -- redis日志
cookie_file = log_path .. "cookie.log";                 -- cookie保存目录

rule_path = "/usr/local/openresty/nginx/conf/wafconfig/" -- 匹配规则路径
admin_cookie = "195300"
sign_in_url = "/api/auth/sign-in"

ipWhitelist={"127.0.0.1"}
--ip白名单，多个ip用逗号分隔,
--支持:
--1)范围划分法 "192.168.0.70-192.168.0.99"
--2)掩码划分法 "192.168.0.0/24"
ipBlocklist={"1.0.0.1","183.200.4.239"}
--ip黑名单，多个ip用逗号分隔
--支持:
--1)范围划分法 "192.168.0.70-192.168.0.99"
--2)掩码划分法 "192.168.0.0/24"

UrlDeny="on"
--是否拦截url访问
CookieMatch="on"
--是否拦截cookie攻击

attack_log = "on" -- 是否开启日志

CCDeny="on"
--是否开启拦截cc攻击(需要nginx.conf的http段增加lua_shared_dict limit 10m;)
urlCCrate="2000/60"
-- ip访问特定url频率（次/秒）
ipCCrate="3000/60"
-- 访问ip频次检测（次/秒）,该值应该是urlCCrate的5-20倍左右



--
--UrlDeny = "on" -- 是否检测url
--CookieMatch = "on" -- 是否检测cookie
--postMatch = "on" -- 是否检测post参数
--whiteModule = "on" -- 是否检测url白名单
--black_fileExt = {"php","jsp"} -- 上传文件后缀检测
--

