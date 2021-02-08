local log_path = "/usr/local/openresty/nginx/logs/hack/";
local filename = log_path .. "redis.log";
local cookie_file = log_path .. "cookie.log";

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
    @comment 写日志操作
    @param
    @return
]]
function wafLog(data, ruletag)
    local request_method = ngx.req.get_method()
    local url = ngx.var.request_uri
    if optionIsOn(attacklog) then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        if ua then
            line = realIp .. " [" .. time .. "] \"" .. request_method .. " " .. servername .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. ruletag .. "\"\n"
        else
            line = realIp .. " [" .. time .. "] \"" .. request_method .. " " .. servername .. url .. "\" \"" .. data .. "\" - \"" .. ruletag .. "\"\n"
        end
 
        local filename = log_path .. "/response.log"
        write(filename, line)
    end
end