---
-- Trusted IPs module
--
-- This module can be used to determine whether or not a given IP address is
-- in the range of trusted IP addresses defined by the `trusted_ips` configuration
-- property.
--
-- Trusted IP addresses are those that are known to send correct replacement
-- addresses for clients (as per the chosen header field, e.g. X-Forwarded-*).
--
-- See [docs.konghq.com/latest/configuration/#trusted_ips](https://docs.konghq.com/latest/configuration/#trusted_ips)
--
-- @module kong.ip
local ipmatcher = require "resty.ipmatcher"


local is_valid_ip_or_cidr
do
  local type = type
  local string = string
  local tostring = tostring

  local ip4_cidrs = {}
  for i = 0, 32 do
    ip4_cidrs[tostring(i)] = true
  end

  local ip6_cidrs = {}
  for i = 0, 128 do
    ip6_cidrs[tostring(i)] = true
  end

  is_valid_ip_or_cidr = function(ip_or_cidr)
    if type(ip_or_cidr) ~= "string" then
      return false
    end

    if ipmatcher.parse_ipv4(ip_or_cidr)
    or ipmatcher.parse_ipv6(ip_or_cidr)
    then
      return true
    end

    local p = string.find(ip_or_cidr, "/", 1, true)
    if not p then
      return false
    end

    local ip = string.sub(ip_or_cidr, 1, p - 1)
    local block = string.sub(ip_or_cidr, p + 1)
    if (ipmatcher.parse_ipv4(ip) and ip4_cidrs[block])
    or (ipmatcher.parse_ipv6(ip) and ip6_cidrs[block])
    then
      return true
    end

    return false
  end
end

---
-- Depending on the `trusted_ips` configuration property,
-- this function will return whether a given ip is trusted or not
--
-- Both ipv4 and ipv6 are supported.
--
-- @function kong.ip.is_trusted
-- @phases init_worker, certificate, rewrite, access, header_filter, body_filter, log
-- @tparam string address A string representing an IP address
-- @treturn boolean `true` if the IP is trusted, `false` otherwise
-- @usage
-- if kong.ip.is_trusted("1.1.1.1") then
--   kong.log("The IP is trusted")
-- end

local function new(self)
  local _IP = {}

  local ips = self.configuration.trusted_ips or {}
  local n_ips = #ips
  local trusted_ips = self.table.new(n_ips, 0)
  local trust_all_ipv4
  local trust_all_ipv6

  -- This is because we don't support unix: that the ngx_http_realip module
  -- supports.  Also as an optimization we will only compile trusted ips if
  -- Kong is not run with the default 0.0.0.0/0, ::/0 aka trust all ip
  -- addresses settings.
  local idx = 1
  for i = 1, n_ips do
    local address = ips[i]

    if is_valid_ip_or_cidr(address) then
      trusted_ips[idx] = address
      idx = idx + 1

      if address == "0.0.0.0/0" then
        trust_all_ipv4 = true

      elseif address == "::/0" then
        trust_all_ipv6 = true
      end
    end
  end

  if #trusted_ips == 0 then
    _IP.is_trusted = function() return false end

  elseif trust_all_ipv4 and trust_all_ipv6 then
    _IP.is_trusted = function() return true end

  else
    -- do not load if not needed
    local matcher = ipmatcher.new(trusted_ips)
    _IP.is_trusted = function(ip)
      return matcher:match(ip) and true or false
    end
  end

  return _IP
end


return {
  new = new,
}
