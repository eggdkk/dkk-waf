local hs = require('hyperscan')
local ret, err = hs.init(hs.HS_WORK_NORMAL)
if not ret then
    ngx.log(ngx.ERR, "hyperscan init failed, ", err)
end

local obj = hs.new(hs.HS_MODE_BLOCK)

local patterns = {
    {id = 1001, pattern = "\\d3",       flag = "iu"},
    {id = 1002, pattern = "\\s{3,5}",   flag = "u"},
    {id = 1003, pattern = "[a-d]{2,7}", flag = ""}
}

-- compile patterns to a database
ret, err = obj:compile(patterns)
if not ret then
    ngx.log(ngx.ERR, "hyperscan block compile failed, ", err)
    return
end

hs.set("test1_obj", obj)