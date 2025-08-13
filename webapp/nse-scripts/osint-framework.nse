-- OSINT Framework NSE Script
-- Author: Nihar Shah
-- Description: Structured OSINT data collection framework

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local dns = require "dns"

description = [[
Comprehensive OSINT framework for passive reconnaissance:
- Domain intelligence gathering
- Social media presence detection
- Email harvesting
- Technology fingerprinting
- Certificate transparency
- DNS enumeration
- Subdomain discovery
]]

author = "Nihar Shah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- OSINT data sources and patterns
local social_platforms = {
    {name = "LinkedIn", pattern = "linkedin%.com/company/", indicator = "linkedin"},
    {name = "Twitter", pattern = "twitter%.com/", indicator = "twitter"},
    {name = "Facebook", pattern = "facebook%.com/", indicator = "facebook"},
    {name = "Instagram", pattern = "instagram%.com/", indicator = "instagram"},
    {name = "YouTube", pattern = "youtube%.com/", indicator = "youtube"}
}

local tech_indicators = {
    {name = "WordPress", pattern = "wp%-content", risk = "medium"},
    {name = "Drupal", pattern = "drupal", risk = "medium"},
    {name = "Joomla", pattern = "joomla", risk = "medium"},
    {name = "Apache", pattern = "Apache/", risk = "low"},
    {name = "Nginx", pattern = "nginx/", risk = "low"},
    {name = "PHP", pattern = "X%-Powered%-By: PHP", risk = "medium"}
}

local email_patterns = {
    "[%w%.%-_]+@[%w%.%-_]+%.%w+",
    "mailto:[%w%.%-_]+@[%w%.%-_]+%.%w+"
}

action = function(host, port)
    local results = {}
    local domain = host.targetname or host.ip
    
    table.insert(results, "=== OSINT FRAMEWORK ANALYSIS ===")
    table.insert(results, string.format("Target: %s", domain))
    
    -- Phase 1: Technology Fingerprinting
    local tech_stack = perform_tech_fingerprinting(host, port)
    if #tech_stack > 0 then
        table.insert(results, "")
        table.insert(results, "TECHNOLOGY STACK:")
        for _, tech in ipairs(tech_stack) do
            table.insert(results, string.format("  • %s (%s risk)", tech.name, tech.risk))
        end
    end
    
    -- Phase 2: Social Media Presence
    local social_presence = detect_social_presence(host, port, domain)
    if #social_presence > 0 then
        table.insert(results, "")
        table.insert(results, "SOCIAL MEDIA PRESENCE:")
        for _, platform in ipairs(social_presence) do
            table.insert(results, string.format("  • %s profile detected", platform))
        end
    end
    
    -- Phase 3: Email Harvesting
    local emails = harvest_emails(host, port)
    if #emails > 0 then
        table.insert(results, "")
        table.insert(results, "EMAIL ADDRESSES:")
        for _, email in ipairs(emails) do
            table.insert(results, string.format("  • %s", email))
        end
    end
    
    -- Phase 4: DNS Intelligence
    local dns_intel = gather_dns_intelligence(domain)
    if #dns_intel > 0 then
        table.insert(results, "")
        table.insert(results, "DNS INTELLIGENCE:")
        for _, record in ipairs(dns_intel) do
            table.insert(results, string.format("  • %s", record))
        end
    end
    
    -- Phase 5: Certificate Analysis
    local cert_info = analyze_certificates(host, port)
    if #cert_info > 0 then
        table.insert(results, "")
        table.insert(results, "CERTIFICATE INTELLIGENCE:")
        for _, info in ipairs(cert_info) do
            table.insert(results, string.format("  • %s", info))
        end
    end
    
    -- Generate OSINT score
    local osint_score = calculate_osint_score(tech_stack, social_presence, emails, dns_intel)
    table.insert(results, "")
    table.insert(results, string.format("OSINT EXPOSURE SCORE: %d/100", osint_score))
    
    return stdnse.format_output(true, results)
end

function perform_tech_fingerprinting(host, port)
    local tech_stack = {}
    local response = http.get(host, port, "/")
    
    if response and response.body and response.header then
        -- Check headers
        local headers = table.concat(response.rawheader or {}, "\n")
        for _, tech in ipairs(tech_indicators) do
            if string.match(headers:lower(), tech.pattern:lower()) or 
               string.match(response.body:lower(), tech.pattern:lower()) then
                table.insert(tech_stack, tech)
            end
        end
    end
    
    return tech_stack
end

function detect_social_presence(host, port, domain)
    local social_presence = {}
    local response = http.get(host, port, "/")
    
    if response and response.body then
        for _, platform in ipairs(social_platforms) do
            if string.match(response.body, platform.pattern) then
                table.insert(social_presence, platform.name)
            end
        end
    end
    
    return social_presence
end

function harvest_emails(host, port)
    local emails = {}
    local paths = {"/", "/contact", "/about", "/team", "/staff"}
    
    for _, path in ipairs(paths) do
        local response = http.get(host, port, path)
        if response and response.body then
            for _, pattern in ipairs(email_patterns) do
                for email in string.gmatch(response.body, pattern) do
                    email = email:gsub("mailto:", "")
                    if not contains(emails, email) then
                        table.insert(emails, email)
                    end
                end
            end
        end
    end
    
    return emails
end

function gather_dns_intelligence(domain)
    local dns_intel = {}
    
    -- MX Records
    local mx_records = dns.query(domain, {dtype = "MX"})
    if mx_records then
        for _, record in ipairs(mx_records) do
            table.insert(dns_intel, string.format("MX: %s (Priority: %d)", record.mx, record.pref))
        end
    end
    
    -- TXT Records
    local txt_records = dns.query(domain, {dtype = "TXT"})
    if txt_records then
        for _, record in ipairs(txt_records) do
            if string.match(record, "v=spf1") then
                table.insert(dns_intel, "SPF record configured")
            elseif string.match(record, "v=DMARC1") then
                table.insert(dns_intel, "DMARC policy configured")
            end
        end
    end
    
    return dns_intel
end

function analyze_certificates(host, port)
    local cert_info = {}
    
    if port.number == 443 or port.service == "https" then
        -- This would require SSL certificate analysis
        table.insert(cert_info, "SSL certificate analysis requires additional libraries")
    end
    
    return cert_info
end

function calculate_osint_score(tech_stack, social_presence, emails, dns_intel)
    local score = 0
    
    -- Technology exposure
    score = score + (#tech_stack * 10)
    
    -- Social media presence
    score = score + (#social_presence * 5)
    
    -- Email exposure
    score = score + (#emails * 8)
    
    -- DNS intelligence
    score = score + (#dns_intel * 3)
    
    return math.min(score, 100)
end

function contains(table, element)
    for _, value in pairs(table) do
        if value == element then
            return true
        end
    end
    return false
end