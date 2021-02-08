require "func"
local log_path = "/usr/local/openresty/nginx/logs/hack/"
local filename = log_path .. "/response.log"


local M = {}




local arg = ngx.req.get_uri_args()
for k,v in pairs(arg) do
    write(filename,"[GET ] ".. k .. "=".. v .."\n")
end

ngx.req.read_body()
local arg = ngx.req.get_post_args()
for k,v in pairs(arg) do
    write(filename,"[POST] ".. k .. "=".. v.."\n")
end
