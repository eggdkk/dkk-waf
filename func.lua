--[[
    @comment 写文件操作
    @param
    @return
]]

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then 
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
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