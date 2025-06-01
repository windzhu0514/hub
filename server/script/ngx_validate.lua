local path = ngx.var.id
local http = require "resty.http"
local requ = http.new()

-- check authorization from local service
local ok, err = requ:connect("unix:/run/server.sock")
if not ok then
        ngx.exit(500)
end

local res, err = requ:request({
method = "HEAD",
path = "/validate/" .. path,
headers = {
        ["Cookie"] = ngx.var.http_cookie,
        ["Host"] = "lamda.local"
},
})
local uid = res.headers["X-ClientId"]
requ:close()
if not (res and res.status == 200) then
        ngx.exit(404)
end

local redis = require "resty.redis"
local client = redis:new()

client:set_timeout(500)

local ok, err = client:connect("unix:/run/redis.sock")
if not ok then
        ngx.exit(503)
end

-- append name to domain
local gw, err = client:get("gw:" .. path)
if err then
        ngx.exit(500)
end
if gw == ngx.null then
        ngx.exit(404)
end

local loc, tok = gw:match("([^,]+),([^,]+)")

ngx.var.target_tok = tok
ngx.var.target_loc = loc
ngx.var.target_uid = uid

ngx.var.target_uri = ngx.re.sub(ngx.var.uri, "^/d/[0-9a-z]+/", "/$1")
ngx.var.target_url = "https://" .. loc

client:close()
