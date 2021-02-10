require "func";
require "config";

-- 全站鉴权
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
    if k == "cookie" then
        res = res .. k .. "=" .. values .. ";\n"
    end
end
local vulnerable_app_session = string.match(res, "vulnerable_app_session=(.-);");
local student_id  = string.match(res, "student_id=(.-);");
if vulnerable_app_session and student_id then
    if select_cookie_md5(ngx.md5(vulnerable_app_session)) ~= ngx.md5(student_id) then
        wafLog(student_id,"篡改Cookie");
        ngx.exit(403);
    end
end

-- 接口指定鉴权
local auth_route_file = rule_path .. "auth_route";
local auth_route = auth_route or readRule(auth_route_file);
write(filename,ngx.var.request_uri)
if auth_route and type(auth_route)=="table" then
    for _,rule in pairs(auth_route) do
        if string.match(ngx.var.request_uri,rule) then
            if student_id ~= admin_cookie then
                wafLog(student_id,"普通用户请求管理员接口");
                ngx.exit(403);
            end
        end
    end
end