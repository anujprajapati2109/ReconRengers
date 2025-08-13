-- Git Repository Reconnaissance NSE Script
-- Author: Nihar Shah
-- Description: Comprehensive Git repository discovery and analysis

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs comprehensive Git repository reconnaissance including:
- .git directory discovery
- Repository enumeration
- Commit history analysis
- Sensitive file detection
- Branch enumeration
- Remote repository discovery
]]

author = "Nihar Shah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- Git-specific paths to check
local git_paths = {
    "/.git/",
    "/.git/config",
    "/.git/HEAD",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/index",
    "/.git/objects/",
    "/.git/refs/",
    "/.git/logs/",
    "/.gitignore",
    "/.gitmodules",
    "/.git/description",
    "/.git/hooks/",
    "/.git/info/refs"
}

-- Sensitive files commonly found in repositories
local sensitive_files = {
    "/.env",
    "/config.json",
    "/database.yml",
    "/secrets.yml",
    "/.aws/credentials",
    "/id_rsa",
    "/id_dsa",
    "/api_keys.txt",
    "/passwords.txt",
    "/backup.sql",
    "/.htpasswd",
    "/web.config",
    "/app.config"
}

action = function(host, port)
    local results = {}
    local git_found = false
    local sensitive_found = {}
    local repositories = {}
    
    -- Check for .git directory exposure
    for _, path in ipairs(git_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 then
                git_found = true
                table.insert(results, string.format("EXPOSED: %s", path))
            elseif response.status == 403 then
                table.insert(results, string.format("FORBIDDEN: %s", path))
            end
        end
    end
    
    -- Check for sensitive files
    for _, file in ipairs(sensitive_files) do
        local response = http.get(host, port, file)
        if response and response.status == 200 then
            table.insert(sensitive_found, file)
            table.insert(results, string.format("SENSITIVE: %s", file))
        end
    end
    
    if git_found or #sensitive_found > 0 then
        table.insert(results, 1, "=== GIT RECONNAISSANCE RESULTS ===")
        return stdnse.format_output(true, results)
    else
        return "No Git exposure detected"
    end
end