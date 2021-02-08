require "func";
require "config";

local res = "";
local h = ngx.req.get_headers();
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
    res = res .. k .. "=" .. values .. ";\n"
    if k == "Cookie" then
        res = res .. k .. "=" .. values .. ";\n"
    end
end

local vulnerable_app_session = string.match(res, "vulnerable_app_session=(.-);");
local student_id  = string.match(res, "student_id=(.-);");

if vulnerable_app_session then
    if student_id then
        if select_cookie_md5(ngx.md5(vulnerable_app_session)) ~= ngx.md5(student_id) then
            ngx.exit(403);
        end
    end
end