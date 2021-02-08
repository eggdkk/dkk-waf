RulePath = "./lualib/waf/wafconf/" -- 匹配规则路径
attacklog = "on" -- 是否开启日志
logdir = "./logs/hack/" -- 日志目录
UrlDeny = "on" -- 是否检测url
CookieMatch = "on" -- 是否检测cookie
postMatch = "on" -- 是否检测post参数
whiteModule = "on" -- 是否检测url白名单
black_fileExt = {"php","jsp"} -- 上传文件后缀检测
ipWhitelist = {"127.0.0.1"} -- 白名单ip列表，支持*做正则
ipBlocklist = {"1.0.0.1"} -- 黑名单ip列表，支持*做正则
CCDeny = "off" -- 是否做cc防攻击检测
CCrate = "100/60" -- ip访问特定url频率（次/秒）
ipCCrate = "600/60" -- ip访问服务器频率（次/秒）

sign_in_url = "/api/auth/sign-in"
