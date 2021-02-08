require "func"
require "config"
local log_path = "/usr/local/openresty/nginx/logs/hack/";
local filename = log_path .. "redis.log";
local cookie_file = log_path .. "cookie.log";
local h = ngx.resp.get_headers();
local res = "";
local request_uri = ngx.var.request_uri
if request_uri == sign_in_url then
    for k, v in pairs(h) do
        local values = ""
        if type(v) == "table" then
            for index, str in pairs(v) do
                values = values .. str;
            end
        end
        if  type(v) ~= "table" then
            values = v
        end
        if k == "set-cookie" then
            res = res .. k .. "=" .. values .. ";\n"
        end
        -- write(filename,res);
    end

    local vulnerable_app_session = string.match(res, "vulnerable_app_session=(.-);");

    local student_id  = string.match(res, "student_id=(.-);");
    write(cookie_file,ngx.md5(student_id) .. ":" .. ngx.md5(vulnerable_app_session).."\n");
    --local handler
    --handler = function (session,id)
    --    -- do some routine job in Lua just like a cron job
    --    if session then
    --        return
    --    end
    --    if id then
    --        return
    --    end
    --    local redis = require "resty.redis"
    --    local red = redis:new()
    --    red:set_timeout(1000) -- 1 sec
    --
    --    local ok, err = red:connect("127.0.0.1", 6379)
    --    if not ok then
    --        ngx.log(ngx.ERR,"failed to connect: "..err)
    --        return
    --    end
    --
    --    -- 请注意这里 auth 的调用过程
    --    local count
    --    count, err = red:get_reused_times()
    --    if 0 == count then
    --        ok, err = red:auth("Ul4YfsfPwRgcDIf5")
    --        if not ok then
    --            ngx.log(ngx.ERR,"failed to auth: "..err)
    --            return
    --        end
    --    elseif err then
    --        ngx.log(ngx.ERR,"failed to get reused times: ".. err)
    --        return
    --    end
    --    ok, err = red:set(tostring(id),tostring(session))
    --    if not ok then
    --        ngx.log(ngx.ERR,"param is : ".. err);
    --        write(filename,id..": "..ngx.md5(session).."\n");
    --        return
    --    end
    --    write(filename, "success\n");
    --
    --    local ok, err = red:set_keepalive(10000, 100)
    --    if not ok then
    --        ngx.log(ngx.ERR,"failed to set keepalive: ".. err)
    --        return
    --    end
    --
    --    ok, err = red:set(tostring(id),tostring(session))
    --    if not ok then
    --        ngx.log(ngx.ERR,"param is : ".. err);
    --        write(filename,id..": "..ngx.md5(session).."\n");
    --        return
    --    end
    --    write(filename, "success\n");
    --end
    --local ok, err = ngx.timer.at(0.001, handler,vulnerable_app_session,student_id);
end