-- Code Exposure Detection NSE Script
-- Author: Nihar Shah
-- Description: Detect exposed source code, secrets, and sensitive information

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Comprehensive code exposure detection including:
- Source code file discovery
- Configuration file exposure
- Backup file detection
- API key and secret detection
- Database credential exposure
- Development environment detection
]]

author = "Nihar Shah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

-- Source code file extensions
local source_extensions = {
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".pl", ".js", ".ts",
    ".java", ".c", ".cpp", ".h", ".cs", ".vb", ".go", ".rs", ".swift"
}

-- Configuration and sensitive files
local sensitive_files = {
    "/.env", "/config.php", "/config.inc.php", "/configuration.php",
    "/wp-config.php", "/database.yml", "/config.yml", "/settings.py",
    "/web.config", "/app.config", "/.htaccess", "/.htpasswd",
    "/composer.json", "/package.json", "/requirements.txt", "/Gemfile",
    "/config.json", "/appsettings.json", "/connectionstrings.config"
}

-- Backup file patterns
local backup_patterns = {
    "%.bak$", "%.backup$", "%.old$", "%.orig$", "%.save$", "%.tmp$",
    "%.swp$", "%~$", "%.copy$", "%.1$", "%.2$", "%.zip$", "%.tar%.gz$"
}

-- Development/debug files
local dev_files = {
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php", "/admin.php",
    "/login.php", "/upload.php", "/shell.php", "/backdoor.php",
    "/readme.txt", "/README.md", "/CHANGELOG.md", "/TODO.txt"
}

-- Secret patterns to search for in content
local secret_patterns = {
    {name = "API Key", pattern = "api[_%-]?key[\"']?%s*[:=]%s*[\"']?([%w%-_]+)", risk = "high"},
    {name = "Database Password", pattern = "password[\"']?%s*[:=]%s*[\"']?([^\"'%s]+)", risk = "critical"},
    {name = "AWS Access Key", pattern = "AKIA[0-9A-Z]{16}", risk = "critical"},
    {name = "Private Key", pattern = "BEGIN [A-Z]+ PRIVATE KEY", risk = "critical"},
    {name = "JWT Token", pattern = "eyJ[A-Za-z0-9%-_=]+%.eyJ[A-Za-z0-9%-_=]+", risk = "high"},
    {name = "Database URL", pattern = "mongodb://[^%s]+", risk = "high"},
    {name = "MySQL Connection", pattern = "mysql://[^%s]+", risk = "high"}
}

action = function(host, port)
    local results = {}
    local exposures = {}
    local secrets_found = {}
    
    table.insert(results, "=== CODE EXPOSURE ANALYSIS ===")
    
    -- Phase 1: Check for sensitive configuration files
    local config_exposures = check_sensitive_files(host, port)
    if #config_exposures > 0 then
        table.insert(results, "")
        table.insert(results, "CONFIGURATION FILE EXPOSURES:")
        for _, exposure in ipairs(config_exposures) do
            table.insert(results, string.format("  🚨 %s", exposure))
            table.insert(exposures, exposure)
        end
    end
    
    -- Phase 2: Check for backup files
    local backup_exposures = check_backup_files(host, port)
    if #backup_exposures > 0 then
        table.insert(results, "")
        table.insert(results, "BACKUP FILE EXPOSURES:")
        for _, exposure in ipairs(backup_exposures) do
            table.insert(results, string.format("  ⚠️  %s", exposure))
            table.insert(exposures, exposure)
        end
    end
    
    -- Phase 3: Check for development files
    local dev_exposures = check_development_files(host, port)
    if #dev_exposures > 0 then
        table.insert(results, "")
        table.insert(results, "DEVELOPMENT FILE EXPOSURES:")
        for _, exposure in ipairs(dev_exposures) do
            table.insert(results, string.format("  🔧 %s", exposure))
            table.insert(exposures, exposure)
        end
    end
    
    -- Phase 4: Scan for secrets in accessible content
    local secret_exposures = scan_for_secrets(host, port)
    if #secret_exposures > 0 then
        table.insert(results, "")
        table.insert(results, "SECRET/CREDENTIAL EXPOSURES:")
        for _, secret in ipairs(secret_exposures) do
            table.insert(results, string.format("  🔑 %s", secret))
            table.insert(secrets_found, secret)
        end
    end
    
    -- Phase 5: Check for source code exposure
    local source_exposures = check_source_code(host, port)
    if #source_exposures > 0 then
        table.insert(results, "")
        table.insert(results, "SOURCE CODE EXPOSURES:")
        for _, exposure in ipairs(source_exposures) do
            table.insert(results, string.format("  📄 %s", exposure))
        end
    end
    
    -- Generate risk assessment
    local risk_score = calculate_exposure_risk(exposures, secrets_found, source_exposures)
    table.insert(results, "")
    table.insert(results, string.format("EXPOSURE RISK SCORE: %d/100", risk_score))
    
    if risk_score > 70 then
        table.insert(results, "🚨 CRITICAL: Immediate action required!")
    elseif risk_score > 40 then
        table.insert(results, "⚠️  HIGH: Significant security concerns")
    elseif risk_score > 20 then
        table.insert(results, "📊 MEDIUM: Some security issues detected")
    else
        table.insert(results, "✅ LOW: Minimal exposure detected")
    end
    
    -- Add recommendations
    if #exposures > 0 or #secrets_found > 0 then
        table.insert(results, "")
        table.insert(results, "RECOMMENDATIONS:")
        table.insert(results, "• Remove sensitive files from web-accessible directories")
        table.insert(results, "• Implement proper access controls (.htaccess, web.config)")
        table.insert(results, "• Use environment variables for sensitive configuration")
        table.insert(results, "• Regular security audits and code reviews")
        table.insert(results, "• Implement secrets management solutions")
    end
    
    return stdnse.format_output(true, results)
end

function check_sensitive_files(host, port)
    local exposures = {}
    
    for _, file in ipairs(sensitive_files) do
        local response = http.get(host, port, file)
        if response and response.status == 200 then
            local size = response.body and #response.body or 0
            table.insert(exposures, string.format("%s (Size: %d bytes)", file, size))
        end
    end
    
    return exposures
end

function check_backup_files(host, port)
    local exposures = {}
    local common_files = {"index", "config", "database", "admin", "login"}
    
    for _, base in ipairs(common_files) do
        for _, pattern in ipairs(backup_patterns) do
            local filename = "/" .. base .. pattern:gsub("%%", ""):gsub("%$", "")
            local response = http.get(host, port, filename)
            if response and response.status == 200 then
                table.insert(exposures, filename)
            end
        end
    end
    
    return exposures
end

function check_development_files(host, port)
    local exposures = {}
    
    for _, file in ipairs(dev_files) do
        local response = http.get(host, port, file)
        if response and response.status == 200 then
            table.insert(exposures, file)
        end
    end
    
    return exposures
end

function scan_for_secrets(host, port)
    local secrets = {}
    local paths_to_scan = {"/", "/config", "/admin", "/api"}
    
    for _, path in ipairs(paths_to_scan) do
        local response = http.get(host, port, path)
        if response and response.body then
            for _, pattern_info in ipairs(secret_patterns) do
                local matches = {}
                for match in string.gmatch(response.body, pattern_info.pattern) do
                    table.insert(matches, match)
                end
                
                if #matches > 0 then
                    table.insert(secrets, string.format("%s found in %s (%s risk)", 
                        pattern_info.name, path, pattern_info.risk))
                end
            end
        end
    end
    
    return secrets
end

function check_source_code(host, port)
    local exposures = {}
    local common_names = {"index", "main", "app", "config", "admin"}
    
    for _, name in ipairs(common_names) do
        for _, ext in ipairs(source_extensions) do
            local filename = "/" .. name .. ext
            local response = http.get(host, port, filename)
            if response and response.status == 200 and response.body then
                -- Check if it's actually source code (contains code patterns)
                if string.match(response.body, "<%?php") or 
                   string.match(response.body, "function%s+%w+") or
                   string.match(response.body, "class%s+%w+") or
                   string.match(response.body, "import%s+") then
                    table.insert(exposures, filename)
                end
            end
        end
    end
    
    return exposures
end

function calculate_exposure_risk(exposures, secrets, source_code)
    local risk = 0
    
    -- Configuration file exposures (high risk)
    risk = risk + (#exposures * 15)
    
    -- Secret exposures (critical risk)
    risk = risk + (#secrets * 25)
    
    -- Source code exposures (medium risk)
    risk = risk + (#source_code * 10)
    
    return math.min(risk, 100)
end