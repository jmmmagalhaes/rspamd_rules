local logger = require "rspamd_logger"
local util = require "rspamd_util"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local rspamd_re = require "rspamd_regexp"
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_util = require "rspamd_util"

local check_cw_dns = ''._cw.xxxxxxxxxxxxxxxxxxxxxxxx.hbl.dq.spamhaus.net.''

local function check_cw_callback ( task, re, lowercase, cryptovalue )
    local parts = task:get_text_parts()
    if not parts then return false end
    local r = task:get_resolver()
    for _, part in ipairs(parts) do
        local words = part:get_words('raw')
        for _, word in ipairs(words) do
        if (lowercase == 1) then word = string.lower(word) end
            local match = re:match(word)
            if match then
                local hash = rspamd_hash.create_specific('sha1', word):hex()
                rspamd_logger.infox('HASH ' .. hash)
        local lookup = hash .. check_cw_dns
        local function dns_cb(_,_,results,err)
            if (not results) then return false end
            if (string.find(tostring(results[1]), '127.0.')) then
                        rspamd_logger.infox('found ' .. cryptovalue .. ' wallet %s (hashed: %s) in Cryptowallet blocklist', word, hash)
                        return task:insert_result('RBL_SPAMHAUS_CW_' .. cryptovalue, 1.0, word);
                    end
                end
                r:resolve_a({ task = task, name = lookup , callback = dns_cb, forced = true })
            end
        end
    end
end

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_BTC",
    score = 7.0,
    description = "BTC found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- BTC regex
        local re = rspamd_re.create_cached('^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$')
        local lowercase = 0
        local cryptovalue = "BTC"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_ETH",
    score = 7.0,
    description = "ETH found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- ETH regex
        local re = rspamd_re.create_cached('^0x[a-fA-F0-9]{40}$')
        local lowercase = 1
        local cryptovalue = "ETH"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_BCH",
    score = 7.0,
    description = "BCH found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- BCH regex
        local re = rspamd_re.create_cached('(?<!=)bitcoincash:(?:q|p)[a-z0-9]{41}')
        local lowercase = 0
        local cryptovalue = "BCH"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_XMR",
    score = 7.0,
    description = "XMR found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- XMR regex
        local re = rspamd_re.create_cached('^(?:4(?:[0-9]|[A-B])(?:.){93})$')
        local lowercase = 0
        local cryptovalue = "XMR"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_LTC",
    score = 7.0,
    description = "LTC found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- LTC regex
        local re = rspamd_re.create_cached('^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$')
        local lowercase = 0
        local cryptovalue = "LTC"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_XRP",
    score = 7.0,
    description = "XRP found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- XRP regex
        local re = rspamd_re.create_cached('^(?:r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{27,35})$')
        local lowercase = 0
        local cryptovalue = "XRP"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

local function spfbl_getkeys(tab)
    local keyset = {}
    for k,v in pairs(tab) do
        keyset[#keyset + 1] = k
    end
    return keyset
end
 
local function spfbl_validate_dns(lstr)
  if lstr:match('%.%.') then
    -- two dots in a row
    return false
  end
  for v in lstr:gmatch('[^%.]+') do
    if not v:match('^[%w-]+$') or v:len() > 63
      or v:match('^-') or v:match('-$') then
      -- too long label or weird labels
      return false
    end
  end
  return true
end
 
local function spfbl_score_table(score)
    local result = 0
    if score >= 0 and score <= 100 then
        if score > 79 then
            result = (score-79)*1/(21)*-1
        elseif score < 50 then
            result = 2-(score-9)*2/(41)
            if result > 2 then result = 2 end
        end
    end
    return result
end
 
local function spfbl_check_score(task, query)
 
    local dns_cb = function(resolver, to_resolve, results, err)
        if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
            rspamd_logger.infox(task, 'DNS query error: %1 = %2', to_resolve, err)
            return
        end
        if results then
            logger.infox(task, 'DNS query: %1 = %2', to_resolve, results)
            local found = false
            for _,result in ipairs(results) do
                local ipstr = result:to_string()
                for m in ipstr:gmatch("127.0.1.(%d+)") do
                    if m and tonumber(m) <= 100 then
                        local score = spfbl_score_table(tonumber(m))
                        score = math.floor(score * 10^2 + 0.5) / 10^2
                        local response = to_resolve .. ' : ' .. ipstr
                        logger.infox(task, '%1 = %2', query.symbol, response)
                        if not task:get_symbol(query.symbol) then
                            task:insert_result(query.symbol, score, response)
                        end
                        found = true
                        break
                    end
                end
                if found then break end
            end
        else
            logger.infox(task, 'DNS query: %1 = no results', to_resolve)
        end
    end
 
    for _, v in ipairs(query.keys) do
        local to_resolve = v .. '.score.spfbl.net'
        if v ~= "localhost" and v ~= "1.0.0.127" and spfbl_validate_dns(to_resolve) then
            task:get_resolver():resolve_a({ task = task, name = to_resolve, callback = dns_cb, forced = true })
        end
    end
 
end
 
local function spfbl_resolve_dns(task, query)
 
    local dns_cb = function(resolver, to_resolve, results, err)
        if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
            rspamd_logger.infox(task, 'DNS query error: %1 = %2', to_resolve, err)
            return
        end
        if results then
            logger.infox(task, 'DNS query: %1 = %2', to_resolve, results)
            local found = false
            for _,result in ipairs(results) do
                local ipstr = result:to_string()
                for symbol,i in pairs(query.returncodes) do
                    if i == ipstr then
                        local response = to_resolve .. ' : ' .. ipstr
                        logger.infox(task, '(%1) %2 = %3', query.symbol, symbol, response)
                        if query.symbol == "SPFBL_RECEIVED" or not task:get_symbol(query.symbol) then
                            task:insert_result(query.symbol, 0)
                            task:insert_result(symbol, 1, response)
                        end
                        found = true
                        break
                    end
                end
                if found then break end
            end
        else
            logger.infox(task, 'DNS query: %1 = no results', to_resolve)
        end
    end
 
    for _, v in ipairs(query.keys) do
        local to_resolve = v .. '.' .. query.dbl
        if v ~= "localhost" and (spfbl_validate_dns(to_resolve) or v:match("^[%w.]+@%w+%.%w+$")) then
            task:get_resolver():resolve_a({ task = task, name = to_resolve, callback = dns_cb })
        end
    end
 
end
 
-- All SPFBL symbols here
local spfbl_symbols = {
    SPFBL_WHITELIST_DOMAIN = {
        SPFBL_WHITELIST_DOMAIN_GOOD_REPUTATION = "127.0.0.2",
        SPFBL_WHITELIST_DOMAIN_PUBLIC_SERVICE = "127.0.0.3",
        SPFBL_WHITELIST_DOMAIN_CORPORATE_SERVICE = "127.0.0.4",
        SPFBL_WHITELIST_DOMAIN_BULK_SENDER = "127.0.0.5"
    },
    SPFBL_DOMAIN = {
        SPFBL_DOMAIN_BAD_REPUTATION = "127.0.0.2",
        SPFBL_DOMAIN_SUSPECTED_SOURCE = "127.0.0.3"
    },
    SPFBL_SERVER = {
        SPFBL_SERVER_BAD_REPUTATION = "127.0.0.2",
        SPFBL_SERVER_SUSPECTED_SOURCE = "127.0.0.3",
        SPFBL_SERVER_END_USER = "127.0.0.4"
    },
    SPFBL_WHITELIST_SERVER = {
        SPFBL_WHITELIST_SERVER_GOOD_REPUTATION = "127.0.0.2",
        SPFBL_WHITELIST_SERVER_PUBLIC_SERVICE = "127.0.0.3",
        SPFBL_WHITELIST_SERVER_CORPORATE_SERVICE = "127.0.0.4"
    },
    SPFBL_RECEIVED = {
        SPFBL_RECEIVED_BAD_REPUTATION = "127.0.0.2",
        SPFBL_RECEIVED_SUSPECTED_SOURCE = "127.0.0.3",
        SPFBL_RECEIVED_END_USER = "127.0.0.4"
    },
    SPFBL_EMAIL = {
        SPFBL_EMAIL_BAD_REPUTATION = "127.0.0.2",
        SPFBL_EMAIL_SUSPECTED_SOURCE = "127.0.0.3"
    },
    SPFBL_SCORE = nil
}
 
local function spfbl_get_symbols(task, key)
    for k, v in pairs(spfbl_symbols) do
        if k == key then
            if task:get_symbol(k) then return true end
            for k2, v2 in pairs(v) do
                if task:get_symbol(k2) then return true end
            end
        end
    end
    return false
end
 
local function spfbl_register_symbols(id_symbol, group)
    for k, v in pairs(group) do
        rspamd_config:register_symbol({name = k, parent = id_symbol, type = 'virtual' })
    end
end
 
local function spfbl_register_dependency(symbol,key)
    for k, v in pairs(spfbl_symbols) do
        if k == key then
            rspamd_config:register_dependency(symbol, key)
            for k2, v2 in pairs(v) do
                rspamd_config:register_dependency(symbol, k2)
            end
        end
    end
    return false
end
 
local spfbl_id_symbol = nil
 
--
 
spfbl_id_symbol = rspamd_config:register_symbol{name = "SPFBL_RECEIVED", type = 'callback', flags = 'empty,no_squeeze', callback = function(task)
    logger.infox(task, 'started SPFBL_RECEIVED')
 
    if spfbl_get_symbols(task, 'SPFBL_SERVER') or spfbl_get_symbols(task, 'SPFBL_WHITELIST_SERVER') then return end
 
    local ip = task:get_from_ip()
    if ip and ip:is_valid() then
        local received_headers = task:get_received_headers()
        for k, v in pairs(received_headers) do
            if v['real_ip'] and v['real_ip']:is_valid() and not v['flags']['artificial'] and not v['real_ip']:is_local() and v['real_ip']:to_string() ~= ip:to_string() then
                local ip_query = {[1] = table.concat(v['real_ip']:inversed_str_octets(), '.') }
                spfbl_resolve_dns(task, { dbl = 'dnsbl.spfbl.net', keys = ip_query, symbol = "SPFBL_RECEIVED", returncodes = spfbl_symbols.SPFBL_RECEIVED })
            end
        end
    end
end}
spfbl_register_symbols(spfbl_id_symbol, spfbl_symbols.SPFBL_RECEIVED)
spfbl_register_dependency("SPFBL_RECEIVED", "SPFBL_SERVER")
spfbl_register_dependency("SPFBL_RECEIVED", "SPFBL_WHITELIST_SERVER")
 
--
 
spfbl_id_symbol = rspamd_config:register_symbol{name = "SPFBL_WHITELIST_DOMAIN", type = 'callback', flags = 'nice,empty,no_squeeze', callback = function(task)
    logger.infox(task, 'started SPFBL_WHITELIST_DOMAIN')
 
    if spfbl_get_symbols(task, 'SPFBL_WHITELIST_SERVER') then return end
 
    local search = {}
 
    if task:get_symbol('R_SPF_ALLOW') then
        local from = task:get_from(1)
        if (from and from[1]) then
            search[from[1].domain:lower()] = 1
        end
    end
    if task:get_symbol('R_DKIM_ALLOW') or task:get_symbol('DMARC_POLICY_ALLOW') then
        local from = task:get_from(2)
        if (from and from[1]) then
            search[from[1].domain:lower()] = 1
        end
    end
 
    local query = spfbl_getkeys(search)
    if #query > 0 then
        spfbl_resolve_dns(task, { dbl = 'dnswl.spfbl.net', keys = query, symbol = "SPFBL_WHITELIST_DOMAIN", returncodes = spfbl_symbols.SPFBL_WHITELIST_DOMAIN  })
    end
 
end}
 
spfbl_register_symbols(spfbl_id_symbol, spfbl_symbols.SPFBL_WHITELIST_DOMAIN)
spfbl_register_dependency("SPFBL_WHITELIST_DOMAIN", "SPFBL_WHITELIST_SERVER")
rspamd_config:register_dependency('SPFBL_WHITELIST_DOMAIN', 'R_SPF_ALLOW')
rspamd_config:register_dependency('SPFBL_WHITELIST_DOMAIN', 'R_DKIM_ALLOW')
rspamd_config:register_dependency('SPFBL_WHITELIST_DOMAIN', 'DMARC_POLICY_ALLOW')
 
--
 
spfbl_id_symbol = rspamd_config:register_symbol{name = "SPFBL_DOMAIN", type = 'callback', flags = 'empty,no_squeeze', callback = function(task)
    logger.infox(task, 'started SPFBL_DOMAIN')
 
    if spfbl_get_symbols(task, 'SPFBL_WHITELIST_DOMAIN') then return end
 
    local search = {}
    local from = task:get_from(1)
    if (from and from[1]) then
        search[from[1].domain:lower()] = 1
    end
 
    from = task:get_from(2)
    if (from and from[1]) then
        search[from[1].domain:lower()] = 1
    end
 
    local replyto = task:get_header('Reply-To')
    if replyto then
        local rt = util.parse_mail_address(replyto, task:get_mempool())
        if (rt and rt[1]) then
            search[rt[1].domain:lower()] = 1
        end
    end
 
    local query = spfbl_getkeys(search)
    if #query > 0 then
        spfbl_resolve_dns(task, { dbl = 'dnsbl.spfbl.net', keys = query, symbol = "SPFBL_DOMAIN", returncodes = spfbl_symbols.SPFBL_DOMAIN })
    end
 
end}
 
spfbl_register_symbols(spfbl_id_symbol, spfbl_symbols.SPFBL_DOMAIN)
spfbl_register_dependency("SPFBL_DOMAIN", "SPFBL_WHITELIST_DOMAIN")
 
---
 
spfbl_id_symbol = rspamd_config:register_symbol{name = "SPFBL_EMAIL", type = 'callback', flags = 'empty,no_squeeze', callback = function(task)
    logger.infox(task, 'started SPFBL_EMAIL')
 
    if spfbl_get_symbols(task, 'SPFBL_DOMAIN') or spfbl_get_symbols(task, 'SPFBL_WHITELIST_DOMAIN') then return end
 
    local search = {}
    if task:get_symbol('FREEMAIL_ENVFROM') then
        local from = task:get_from(1)
        if (from and from[1]) then
            search[from[1].addr] = 1
        end
    end
 
    if task:get_symbol('FREEMAIL_FROM') then
        local from = task:get_from(2)
            if (from and from[1]) then
            search[from[1].addr] = 1
        end
    end
 
    if task:get_symbol('FREEMAIL_REPLYTO') then
        local replyto = task:get_header('Reply-To')
        if replyto then
            local rt = util.parse_mail_address(replyto, task:get_mempool())
            if (rt and rt[1]) then
                lua_util.remove_email_aliases(rt[1])
                search[rt[1].addr] = 1
            end
        end
    end 
 
    local query = spfbl_getkeys(search)
    if #query > 0 then
        spfbl_resolve_dns(task, { dbl = 'dnsbl.spfbl.net', keys = query, symbol = "SPFBL_EMAIL", returncodes = spfbl_symbols.SPFBL_EMAIL })
    end
 
end}
 
spfbl_register_symbols(spfbl_id_symbol, spfbl_symbols.SPFBL_EMAIL)
spfbl_register_dependency("SPFBL_EMAIL", "SPFBL_WHITELIST_DOMAIN")
spfbl_register_dependency("SPFBL_EMAIL", "SPFBL_DOMAIN")
rspamd_config:register_dependency('SPFBL_EMAIL', 'FREEMAIL_ENVFROM')
rspamd_config:register_dependency('SPFBL_EMAIL', 'FREEMAIL_FROM')
rspamd_config:register_dependency('SPFBL_EMAIL', 'FREEMAIL_REPLYTO')
 
---
 
spfbl_id_symbol = rspamd_config:register_symbol{name = "SPFBL_SCORE", type = 'callback', flags = 'nice,empty,no_squeeze', callback = function(task)
    logger.infox(task, 'started SPFBL_SCORE')
 
    -- check IP/RDNS score
    if not (spfbl_get_symbols(task, 'SPFBL_SERVER') or spfbl_get_symbols(task, 'SPFBL_WHITELIST_SERVER')) then
        local search = {}
 
        local ip = task:get_from_ip()
        if ip and ip:is_valid() and not ip:is_local() then
            search[table.concat(ip:inversed_str_octets(), '.')] = 1
        end
 
        local rdns = task:get_hostname()
        if not (rdns == nil or rdns == '' or rdns == 'unknown' or rdns == 'localhost') then
            search[rdns:lower()] = 1
        end
 
        local query = spfbl_getkeys(search)
        if #query > 0 then
            spfbl_check_score(task, { keys = query, symbol = "SPFBL_SCORE_SERVER" })
        end
    end
 
    -- check domain score
    if not (spfbl_get_symbols(task, 'SPFBL_DOMAIN') or spfbl_get_symbols(task, 'SPFBL_WHITELIST_DOMAIN') or spfbl_get_symbols(task, 'SPFBL_EMAIL')) then
        local search = {}
 
        if task:get_symbol('R_SPF_ALLOW') then
            local from = task:get_from(1)
            if (from and from[1]) then
                search[from[1].domain:lower()] = 1
            end
        end
        if task:get_symbol('R_DKIM_ALLOW') or task:get_symbol('DMARC_POLICY_ALLOW') then
            local from = task:get_from(2)
            if (from and from[1]) then
                search[from[1].domain:lower()] = 1
            end
        end
 
        local replyto = task:get_header('Reply-To')
        if replyto then
            local rt = util.parse_mail_address(replyto, task:get_mempool())
            if (rt and rt[1]) then
                lua_util.remove_email_aliases(rt[1])
                search[rt[1].addr] = 1
            end
        end
 
        local query = spfbl_getkeys(search)
        if #query > 0 then
            spfbl_check_score(task, { keys = query, symbol = "SPFBL_SCORE_DOMAIN" })
        end
 
    end
 
end}
 
rspamd_config:register_symbol({name = "SPFBL_SCORE_SERVER", parent = spfbl_id_symbol, type = 'virtual' })
rspamd_config:register_symbol({name = "SPFBL_SCORE_DOMAIN", parent = spfbl_id_symbol, type = 'virtual' })
spfbl_register_dependency("SPFBL_SCORE", "SPFBL_WHITELIST_DOMAIN")
spfbl_register_dependency("SPFBL_SCORE", "SPFBL_DOMAIN")
spfbl_register_dependency("SPFBL_SCORE", "SPFBL_WHITELIST_SERVER")
spfbl_register_dependency("SPFBL_SCORE", "SPFBL_SERVER")
spfbl_register_dependency("SPFBL_SCORE", "SPFBL_EMAIL")
rspamd_config:register_dependency('SPFBL_SCORE', 'R_SPF_ALLOW')
rspamd_config:register_dependency('SPFBL_SCORE', 'R_DKIM_ALLOW')
rspamd_config:register_dependency('SPFBL_SCORE', 'DMARC_POLICY_ALLOW')
 
-- Adding conditions to all symbols
for k, v in pairs(spfbl_symbols) do
    rspamd_config:add_condition(k, function(task)
        if task:get_user() then return false end
        local ip = task:get_from_ip()
        if ip and ip:is_local() then return false end
        return true
    end)
end
