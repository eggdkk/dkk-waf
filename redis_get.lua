require "func"
require "config"
local log_path = "/usr/local/openresty/nginx/logs/hack/";

local filename = log_path .. "redis.log";

local h = ngx.resp.get_headers();
local res = "";
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
    write(filename,res);
end