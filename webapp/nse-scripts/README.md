# NSE Scripts for Git & OSINT Reconnaissance

## Overview
Custom NSE (Nmap Scripting Engine) scripts for comprehensive Git repository and OSINT reconnaissance when APIs are not available.

## Scripts Included

### 1. git-recon.nse
**Purpose**: Comprehensive Git repository discovery and analysis
**Categories**: discovery, safe

**Features**:
- .git directory exposure detection
- Sensitive file discovery
- Repository enumeration
- Commit history analysis
- Remote repository discovery

**Usage**:
```bash
# Basic scan
nmap --script git-recon target.com

# With specific ports
nmap -p 80,443 --script git-recon target.com

# Verbose output
nmap --script git-recon --script-args verbose=1 target.com
```

### 2. osint-framework.nse
**Purpose**: Structured OSINT data collection framework
**Categories**: discovery, safe

**Features**:
- Technology fingerprinting
- Social media presence detection
- Email harvesting
- DNS intelligence gathering
- Certificate analysis
- OSINT exposure scoring

**Usage**:
```bash
# Basic OSINT scan
nmap --script osint-framework target.com

# Full port range
nmap -p- --script osint-framework target.com

# With timing template
nmap -T4 --script osint-framework target.com
```

### 3. code-exposure.nse
**Purpose**: Detect exposed source code, secrets, and sensitive information
**Categories**: vuln, safe

**Features**:
- Source code file discovery
- Configuration file exposure
- Backup file detection
- API key and secret detection
- Database credential exposure
- Development environment detection

**Usage**:
```bash
# Code exposure scan
nmap --script code-exposure target.com

# Web application focus
nmap -p 80,443,8080,8443 --script code-exposure target.com

# Comprehensive scan
nmap --script "code-exposure,git-recon" target.com
```

## Installation

1. Copy scripts to Nmap scripts directory:
```bash
# Linux/Mac
sudo cp *.nse /usr/share/nmap/scripts/

# Windows
copy *.nse "C:\Program Files (x86)\Nmap\scripts\"
```

2. Update script database:
```bash
nmap --script-updatedb
```

## Advanced Usage

### Combined Reconnaissance
```bash
# Full Git & OSINT reconnaissance
nmap --script "git-recon,osint-framework,code-exposure" target.com

# With output to file
nmap --script "git-recon,osint-framework,code-exposure" -oA recon_results target.com
```

### Stealth Scanning
```bash
# Slow and stealthy
nmap -T1 --script git-recon target.com

# Random order with delays
nmap --randomize-hosts --script osint-framework target.com
```

### Multiple Targets
```bash
# Scan multiple targets
nmap --script git-recon target1.com target2.com target3.com

# From file
nmap --script osint-framework -iL targets.txt
```

## Script Arguments

### git-recon.nse
- `verbose`: Enable verbose output (0/1)
- `timeout`: HTTP timeout in seconds (default: 10)

### osint-framework.nse
- `social-only`: Only check social media presence (0/1)
- `tech-only`: Only perform technology fingerprinting (0/1)

### code-exposure.nse
- `deep-scan`: Enable deep scanning for more file types (0/1)
- `secrets-only`: Only scan for secrets and credentials (0/1)

## Example Commands

```bash
# Quick Git exposure check
nmap --script git-recon --script-args verbose=1 example.com

# OSINT with social media focus
nmap --script osint-framework --script-args social-only=1 example.com

# Deep code exposure scan
nmap --script code-exposure --script-args deep-scan=1 example.com

# Combined scan with custom timeout
nmap --script "git-recon,code-exposure" --script-args timeout=15 example.com
```

## Output Interpretation

### Risk Levels
- **CRITICAL**: Immediate action required (exposed credentials, private keys)
- **HIGH**: Significant security concern (configuration files, API keys)
- **MEDIUM**: Moderate risk (technology disclosure, backup files)
- **LOW**: Minimal risk (general information disclosure)

### Common Findings
- `.git` directory exposure → **CRITICAL**
- Database credentials → **CRITICAL**
- API keys in source → **HIGH**
- Configuration files → **HIGH**
- Technology fingerprints → **MEDIUM**
- Social media profiles → **LOW**

## Integration with Web Dashboard

The NSE scripts are automatically integrated with the web dashboard through the Git OSINT Framework. When APIs are unavailable, the system falls back to NSE script execution.

## Troubleshooting

### Common Issues
1. **Permission denied**: Run with sudo/administrator privileges
2. **Script not found**: Ensure scripts are in correct directory and database is updated
3. **Timeout errors**: Increase timeout value or use slower timing template

### Debug Mode
```bash
# Enable debug output
nmap --script git-recon --script-args debug=1 target.com

# Verbose Nmap output
nmap -v --script osint-framework target.com
```

## Legal Notice

These scripts are for authorized security testing only. Ensure you have proper permission before scanning any targets. Unauthorized scanning may violate laws and regulations.

## Author

**Nihar Shah**  
AnujScan Pro Security Suite  
Version 2.0 Professional Edition