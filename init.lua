require "func"
require "config"
local redis = require "resty.redis"
local red = redis:new()

local ck = require "cookie"
local cookie, err = ck:new()

local log_path = "/usr/local/openresty/nginx/logs/hack/"
local filename = log_path .. "redis.log"



red:set_timeout(1000) -- 1 sec

local ok, err = red:connect("127.0.0.1", 6379)
if not ok then
    ngx.set("failed to connect: ",err)
    return
end

-- 请注意这里 auth 的调用过程
local count
count, err = red:get_reused_times()
if 0 == count then
    ok, err = red:auth("Ul4YfsfPwRgcDIf5")
    if not ok then
        ngx.set("failed to auth: ",err)
        return
    end
elseif err then
    ngx.set("failed to get reused times: ", err)
    return
end

-- 连接池大小是100个，并且设置最大的空闲时间是 10 秒
local ok, err = red:set_keepalive(10000, 100)
if not ok then
    ngx.set("failed to set keepalive: ", err)
    return
end
local request_uri = ngx.var.request_uri
if request_uri == sign_in_url then
    if not cookie then
        ngx.log(ngx.ERR, err)
        return ngx.say("assign failed:",err)
    end
    local student_id, err = cookie:get('student_id')
    local vulnerable_app_session, err = cookie:get('vulnerable_app_session')
    if not student_id then
        ngx.log(ngx.ERR, err)
        return ngx.say("get failed:",err)
    end
    write(filename,student_id.."\n"..vulnerable_app_session.."\n")
end
-- ok, err = red:set("dog", "an animal")
-- if not ok then
--     ngx.set("failed to set dog: ",err)
--     return
-- end

