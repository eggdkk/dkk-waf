require "config"


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
    local file = io.open(file_name, 'r')
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
function getClientIp()
    IP  = ngx.var.remote_addr
    if IP == nil then
        IP  = "unknown"
    end
    return IP
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
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local time =ngx.now()*1000
        if ua then
            line = '{"id":'..time..',"realIp":"'..realIp .. '", "time":"' .. time .. '","request_method":"' .. request_method .. '", "url":"' .. url .. '","ua":"'.. ua ..'","data":"' .. data .. '", "ruletag":"' .. rule_tag .. '"}\n';
        else
            line = '{"id":'..time..',"realIp":"'..realIp .. '", "time":"' .. time .. '","request_method":"' .. request_method .. '", "url":"' .. url .. '","data":"' .. data .. '", "ruletag":"' .. rule_tag .. '"}\n';
        end
        local filename = log_path .. "/response.log"
        write(filename, line)
    end
end