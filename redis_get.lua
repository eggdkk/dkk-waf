require "func"
require "config"
local log_path = "/usr/local/openresty/nginx/logs/hack/";
local filename = log_path .. "redis.log";
local h = ngx.resp.get_headers();
local res = "";

local mysql = require "resty.mysql"
-- 初始化数据库对象
local db, err = mysql:new()
if not db then
    ngx.say("failed to instantiate mysql: ", err)
    return
end
-- 设置连接超时
db:set_timeout(1000)
-- 设置连接最大空闲时间，连接池容量
db:set_keepalive(10000, 100)

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

local student_id string.match(res, "student_id=(.-);");