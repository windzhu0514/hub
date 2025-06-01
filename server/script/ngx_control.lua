local redis = require "resty.redis"
local client = redis:new()

local name = ngx.var.ssl_preread_server_name
client:set_timeout(500)

local ok, err = client:connect("unix:/run/redis.sock")
if not ok then
        ngx.exit(444)
end

local gw, err = client:get("gw:" .. name)
if err then
        ngx.exit(444)
end
if gw == ngx.null then
        ngx.exit(444)
end
local loc, tok = gw:match("([^,]+),([^,]+)")

ngx.var.target_loc = loc
client:close()