require "config";

local ngx_match = ngx.re.match;
local unescape=ngx.unescape_uri;
local optionIsOn = function (options) return options == "on" and true or false end

CCDeny = optionIsOn(CCDeny)


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
        local filename = log_path .. "response.log"
        write(filename, line);
    end
end

function url(url_rules)
    if UrlDeny then
        for _,rule in pairs(url_rules) do
            local m, err = ngx.re.match("Tinywan, 1234", "([0-9])[0-9]+");
            write(log_path.."bug.txt",m)
            --write(log_path.."bug.txt",tostring(ngx.re.match(ngx.var.request_uri,rule,"isjo")).."\n"..ngx.var.request_uri.."\n");
            if rule ~="" and ngx.re.match(ngx.var.request_uri,rule,"isjo") then
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
            if rule ~="" and string.match(string.lower(ua),rule) then
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
        if ngx_match(unescape(ngx.var.request_uri),rule) then
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

--数字转换为八位二进制
function byte2bin(n)
    local t = {}
    for i=7,0,-1 do
        t[#t+1] = math.floor(n / 2^i)
        n = n % 2^i
    end
    return table.concat(t)
end

--拼接IP每部分的二进制，返回IP完整的二进制
function IP2bin(ip_s)
    local IP_p1,IP_p2,IP_p3,IP_p4=string.match(ip_s, "(%d+).(%d+).(%d+).(%d+)")
    ip_str = byte2bin(IP_p1)..byte2bin(IP_p2)..byte2bin(IP_p3)..byte2bin(IP_p4)
    return ip_str
end

--判断二进制IP是否在属于某网段
function IpBelongToNetwork(bin_ip,bin_network,mask)
    if (string.sub(bin_ip,1,mask) == string.sub(bin_network,1,mask)) then
        return true
    else
        return false
    end
end

--字符串分割函数
function split(str,delimiter)
    local dLen = string.len(delimiter)
    local newDeli = ''
    for i=1,dLen,1 do
        newDeli = newDeli .. "["..string.sub(delimiter,i,i).."]"
    end
    local locaStart,locaEnd = string.find(str,newDeli)
    local arr = {}
    local n = 1
    while locaStart ~= nil
    do
        if locaStart>0 then
            arr[n] = string.sub(str,1,locaStart-1)
            n = n + 1
        end
        str = string.sub(str,locaEnd+1,string.len(str))
        locaStart,locaEnd = string.find(str,newDeli)
    end
    if str ~= nil then
        arr[n] = str
    end
    return arr
end

function ipToDecimal(ckip)
    local n = 4
    local decimalNum = 0
    local pos = 0
    for s, e in function() return string.find(ckip, '.', pos, true) end do
        n = n - 1
        decimalNum = decimalNum + string.sub(ckip, pos, s-1) * (256 ^ n)
        pos = e + 1
        if n == 1 then decimalNum = decimalNum + string.sub(ckip, pos, string.len(ckip)) end
    end
    return decimalNum
end


function block_ip()
    if next(ipBlocklist) ~= nil then
        local cIP = get_client_ip()
        local numIP = 0
        if cIP ~= "unknown" then
            numIP = tonumber(ipToDecimal(cIP))
        end
        for _,ip in pairs(ipBlocklist) do
            local s, e = string.find(ip, '-', 0, true)
            local x, j = string.find(ip, '/', 0, true)
            --IP字符串中不存在"-"、"/"等划分网段标识
            if s == nil and x == nil and cIP == ip then
                wafLog("-","IP黑名单配置错误");
                ngx.exit(403)
                return true
                --范围划分法
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                    wafLog(tostring(cIP),"IP黑名单拦截");
                    ngx.exit(403)
                    return true
                end
                --掩码划分法
            elseif x ~= nil then
                local ip_list = split(ip, "/")
                if IpBelongToNetwork(IP2bin(cIP),IP2bin(ip_list[1]),ip_list[2]) then
                    wafLog(tostring(cIP),"IP黑名单拦截");
                    ngx.exit(403);
                    return true
                end
            end
        end
    end
    return false
end

function white_ip()
    if next(ipWhitelist) ~= nil then
        local cIP = get_client_ip()
        local numIP = 0
        if cIP ~= "unknown" then
            numIP = tonumber(ipToDecimal(cIP))
        end
        for _,ip in pairs(ipWhitelist) do
            local s, e = string.find(ip, '-', 0, true)
            local x, j = string.find(ip, '/', 0, true)
            --IP字符串中不存在"-"、"/"等划分网段标识
            if s == nil and x == nil and cIP == ip then
                return true
                --范围划分法
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                    return true
                end
                --掩码划分法
            elseif x ~= nil then
                local ip_list = split(ip, "/")
                if IpBelongToNetwork(IP2bin(cIP),IP2bin(ip_list[1]),ip_list[2]) then
                    return true
                end
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        --local uri = ngx.var.uri
        --改用request_uri,并且进行base64，以防特殊符号出问题。解决使用URL传参导致触发CC异常
        --base64url是Base64编码的一种改进形式，它用“－”和“_”替代了“＋”和“／”，编码后长度不是4的倍数时也不使用“＝”填补，可以安全地用在URL 里。
        local uri = b64.encode_base64url(tostring(ngx.var.request_uri))
        local CCcount = tonumber(string.match(urlCCrate, "(.*)/"))
        local CCseconds = tonumber(string.match(urlCCrate, "/(.*)"))
        local ipCCcount = tonumber(string.match(ipCCrate, "(.*)/"))
        local ipCCseconds = tonumber(string.match(ipCCrate, "/(.*)"))
        local now_ip = getClientIp()
        local token = now_ip .. '.' ..uri
        local urllimit = ngx.shared.urllimit
        local iplimit = ngx.shared.iplimit
        local req, _ = urllimit:get(token)
        local ipreq, _ = iplimit:get(now_ip)

        if req then -- ip访问url频次检测
            if req > CCcount then
                wafLog("-", "IP get url over times. ")
                --say_html("IpURL频繁访问限制，请稍后再试")
                ngx.exit(403);
                --        say_html(token)
                return true
            else
                urllimit:incr(token, 1)
            end
        else
            urllimit:set(token, 1, CCseconds)
        end

        if ipreq then -- 访问ip频次检测
            if ipreq > ipCCcount then
                wafLog("-", "IP get host over times. ")
                --say_html("IP频繁访问限制，请稍后再试")
                ngx.exit(403);
                return true
            else
                iplimit:incr(now_ip, 1)
            end
        else
            iplimit:set(now_ip, 1, ipCCseconds)
        end
    end

    return false
end
