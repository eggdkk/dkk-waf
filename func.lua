require "config"
local ngx_match = ngx.re.match
urlrules = readRule("url");
uarules = readRule('user-agent');
argsrules = readRule('args');
postrules = readRule('post');
ckrules = readRule('cookie');

--[[
    @comment 写文件操作
    @param
    @return
]]

function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

--[[
    @comment 读文件操作
    @param
    @return
]]
function open_file(file_name)
    local f = io.open(file_name, 'r')
    if not f then
        return nil
    end
    local string = f:read("*all")
    f:close()
    return string
end

--[[
    @comment 逐行读取配置文件
    @param 文件名
    @return
]]
function readRule(file_name)
    local file = io.open(rule_path .. file_name, 'r')
    if file == nil then
        return
    end
    local ret = {}
    for line in file:lines() do
        table.insert(ret, line)
    end
    file:close()

    return ret
end


--[[
    @comment 根据token查询cookie
]]
function select_cookie_md5(token_md5)
    if not token_md5 then
        return nil
    end
    return string.match(open_file(cookie_file),"([%w]-):"..token_md5);
end
--[[
    @comment 获取客户端ip
]]
--function getClientIp()
--    IP  = ngx.var.remote_addr
--    if IP == nil then
--        IP  = "unknown"
--    end
--    return IP
--end
function get_client_ip()
    local headers=ngx.req.get_headers()
    local ip=headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    return ip
end

local optionIsOn = function (options) return options == "on" and true or false end

--[[
    @comment 写日志操作
    @param
    @return
]]
function wafLog(data, rule_tag)
    local request_method = ngx.req.get_method()
    local url = ngx.var.request_uri
    if optionIsOn(attack_log) then
        local realIp = get_client_ip();
        local ua = ngx.var.http_user_agent
        local local_time = ngx.localtime()
        local time =ngx.now()*1000
        if ua then
            line = '{"id":'..time..',"realIp":"'..realIp .. '", "time":"' .. local_time .. '","request_method":"' .. request_method .. '", "url":"' .. url .. '","ua":"'.. ua ..'","data":"' .. data .. '", "ruletag":"' .. rule_tag .. '"}\n';
        else
            line = '{"id":'..time..',"realIp":"'..realIp .. '", "time":"' .. local_time .. '","request_method":"' .. request_method .. '", "url":"' .. url .. '","data":"' .. data .. '", "ruletag":"' .. rule_tag .. '"}\n';
        end
        local filename = log_path .. "/response.log"
        write(filename, line)
    end
end

function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngx_match(ngx.var.request_uri,rule,"isjo") then
                wafLog("-", "url in attack rules: " .. rule)
                --say_html("URL拦截命中")
                ngx.exit(403);
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngx_match(ua,rule,"isjo") then
                wafLog("-", "ua in attack rules: " .. rule)
                --say_html("UA拦截命中")
                ngx.exit(403);
                return true
            end
        end
    end
    return false
end

function args()
    for _,rule in pairs(argsrules) do
        if ngx_match(unescape(ngx.var.request_uri),rule,"isjo") then
            wafLog("-",rule)
            --say_html("URL请求异常")
            ngx.exit(403);
            return true
        end
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                local t={}
                for k,v in pairs(val) do
                    if v == true then
                        v=""
                    end
                    table.insert(t,v)
                end
                data=table.concat(t, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngx_match(unescape(data),rule,"isjo") then
                wafLog("-", "args in attack rules: " .. rule .. " data: " .. tostring(data))
                --say_html("URL参数异常")
                ngx.exit(403);
                return true
            end
        end
    end
    return false
end

--body内容检查
function body(data)
    if not FileContentCheck then
        return false
    end
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngx_match(unescape(data),rule,"isjo") then
            wafLog(data,rule);
            --say_html("Body POST拦截命中")
            ngx.exit(403);
            return true
        end
    end
    return false
end


function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngx_match(ck,rule,"isjo") then
                wafLog("-", "cookie in attack rules: " .. rule)
                --say_html("Cookie异常,疑似攻击")
                ngx.exit(403);
                return true
            end
        end
    end
    return false
end