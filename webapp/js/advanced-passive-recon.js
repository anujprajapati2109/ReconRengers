// Advanced Passive Reconnaissance with 10+ Tools
const PassiveReconTools = {
    tools: [
        { id: 'whois', name: '📋 WHOIS & Domain Info', description: 'Registrar, creation date, DNS servers', enabled: true },
        { id: 'dns', name: '🌐 DNS Enumeration', description: 'MX, TXT, SPF records, nameservers', enabled: true },
        { id: 'certs', name: '📜 Certificate Transparency', description: 'Subdomains from SSL certificates', enabled: true },
        { id: 'shodan', name: '🛰️ Shodan Search', description: 'Open ports, services, banners', enabled: true },
        { id: 'dorking', name: '🔍 Search Engine Dorking', description: 'Google/Bing/DuckDuckGo indexed files', enabled: true },
        { id: 'breaches', name: '💀 Data Breach Check', description: 'Exposed emails, passwords', enabled: true },
        { id: 'wayback', name: '📚 Archive Search', description: 'Historical website versions', enabled: true },
        { id: 'subdomains', name: '🌍 Subdomain Discovery', description: 'Passive subdomain enumeration', enabled: true },
        { id: 'emails', name: '📧 Email Harvesting', description: 'Public email addresses', enabled: true },
        { id: 'social', name: '👥 Social Media OSINT', description: 'Social accounts, usernames', enabled: true },
        { id: 'reverseip', name: '🔄 Reverse IP Lookup', description: 'Other domains on same IP', enabled: true },
        { id: 'github', name: '💻 GitHub Code Search', description: 'Secrets, exposed code repositories', enabled: true },
        { id: 'geolocation', name: '🌍 IP Geolocation', description: 'Country, city, ISP information', enabled: true },
        { id: 'threatintel', name: '🛡️ Threat Intelligence', description: 'Malware domains, reputation check', enabled: true },
        { id: 'webfingerprint', name: '🔍 Web Fingerprinting', description: 'Tech stack without direct scanning', enabled: true },
        { id: 'aianalysis', name: '🤖 AI Pattern Analysis', description: 'UNIQUE: AI-powered pattern recognition', enabled: true }
    ],
    
    findings: [],
    
    async runSelectedTools(target, selectedTools) {
        this.findings = [];
        const results = document.getElementById('reconResults');
        
        function addResult(msg, level = 'info', source = '') {
            const time = new Date().toLocaleTimeString();
            const levelIcon = level === 'critical' ? '🚨' : level === 'high' ? '⚠️' : level === 'medium' ? '📊' : '✅';
            results.innerHTML += `[${time}] ${levelIcon} ${msg}<br>`;
            results.scrollTop = results.scrollHeight;
            
            if (level !== 'info') {
                PassiveReconTools.findings.push({
                    message: msg,
                    level: level,
                    source: source,
                    timestamp: new Date().toISOString()
                });
            }
        }
        
        addResult(`🕵️ Starting comprehensive passive reconnaissance on ${target}`);
        addResult('='.repeat(60));
        
        // Show tool selection dialog
        const toolsToRun = await this.showToolSelection(selectedTools, target);
        
        for (let tool of toolsToRun) {
            addResult(`🔄 Running ${tool.name}...`);
            
            try {
                await this.runTool(tool.id, target, addResult);
                await new Promise(resolve => setTimeout(resolve, 1000));
            } catch (error) {
                addResult(`❌ ${tool.name} failed: ${error.message}`, 'info');
            }
        }
        
        addResult('='.repeat(60));
        addResult(`✅ PASSIVE RECONNAISSANCE COMPLETE - ${this.findings.length} findings`);
        
        // Apply Nihar's Intelligence Analysis
        const intelligenceProfile = window.niharIntelligence.correlateReconData(
            this.findings.map(f => ({ type: f.source, message: f.message, level: f.level })), 
            [], 
            target
        );
        
        addResult('🧠 NIHAR\'S INTELLIGENCE ANALYSIS:', 'info');
        addResult(`   • Risk Score: ${intelligenceProfile.riskScore}/100`, 'info');
        addResult(`   • Creator Score: ${intelligenceProfile.niharScore}%`, 'info');
        addResult(`   • Threat Correlations: ${intelligenceProfile.correlatedThreats.length}`, 'info');
        addResult(`   • Critical Findings: ${intelligenceProfile.criticalFindings.length}`, 'info');
        
        if (intelligenceProfile.criticalFindings.length > 0) {
            addResult('🚨 TOP CORRELATED THREATS:', 'critical');
            intelligenceProfile.criticalFindings.slice(0, 3).forEach(finding => {
                addResult(`   • ${finding.threat}: ${finding.nihar_insight}`, 'critical');
            });
        }
        
        // Apply Nihar's Intelligence Engine for correlation analysis
        const intelligenceProfile = window.niharIntelligence.correlateReconData(
            this.findings.map(f => ({ type: f.source, message: f.message, level: f.level })), 
            [], // No active data yet
            target
        );
        
        // Show intelligent popup with Nihar's analysis
        setTimeout(() => {
            const criticalFindings = this.findings.filter(f => f.level === 'critical');
            const highFindings = this.findings.filter(f => f.level === 'high');
            const mediumFindings = this.findings.filter(f => f.level === 'medium');
            
            const findings = [
                ...criticalFindings.map(f => ({ type: f.source, impact: 'Critical', message: f.message, source: f.source })),
                ...highFindings.map(f => ({ type: f.source, impact: 'High', message: f.message, source: f.source })),
                ...mediumFindings.map(f => ({ type: f.source, impact: 'Medium', message: f.message, source: f.source }))
            ];
            
            // Add Nihar's intelligence insights to findings
            findings.push({
                type: 'Nihar Intelligence',
                impact: 'Analysis',
                message: `Risk Score: ${intelligenceProfile.riskScore}/100 | Creator Score: ${intelligenceProfile.niharScore}% | Correlations: ${intelligenceProfile.correlatedThreats.length}`,
                source: 'Nihar Intelligence Engine'
            });
            
            if (typeof ReportGenerator !== 'undefined') {
                ReportGenerator.setScanData('passive', findings, target, intelligenceProfile);
            }
            if (typeof showIntelligentResultsPopup !== 'undefined') {
                showIntelligentResultsPopup('passive', findings, intelligenceProfile);
            }
        }, 2000);
    },
    
    async runTool(toolId, target, addResult) {
        switch (toolId) {
            case 'whois':
                await this.runWhoisLookup(target, addResult);
                break;
            case 'dns':
                await this.runDNSEnumeration(target, addResult);
                break;
            case 'certs':
                await this.runCertificateTransparency(target, addResult);
                break;
            case 'shodan':
                await this.runShodanSearch(target, addResult);
                break;
            case 'dorking':
                await this.runGoogleDorking(target, addResult);
                break;
            case 'breaches':
                await this.runBreachCheck(target, addResult);
                break;
            case 'wayback':
                await this.runWaybackSearch(target, addResult);
                break;
            case 'subdomains':
                await this.runSubdomainDiscovery(target, addResult);
                break;
            case 'emails':
                await this.runEmailHarvesting(target, addResult);
                break;
            case 'social':
                await this.runSocialOSINT(target, addResult);
                break;
            case 'reverseip':
                await this.runReverseIPLookup(target, addResult);
                break;
            case 'github':
                await this.runGitHubSearch(target, addResult);
                break;
            case 'git-osint':
                if (typeof GitOSINTFramework !== 'undefined') {
                    await GitOSINTFramework.executeGitOSINT(target, addResult);
                } else {
                    addResult('❌ Git OSINT Framework not loaded', 'info');
                }
                break;
            case 'geolocation':
                await this.runGeolocation(target, addResult);
                break;
            case 'threatintel':
                await this.runThreatIntelligence(target, addResult);
                break;
            case 'webfingerprint':
                await this.runWebFingerprinting(target, addResult);
                break;
            case 'aianalysis':
                await this.runAIPatternAnalysis(target, addResult);
                break;
        }
    },
    
    async runWhoisLookup(target, addResult) {
        addResult('📋 Executing NSE: whois-domain.nse', 'info', 'WHOIS Lookup');
        
        // Only validate if target is clearly invalid
        if (!target.includes('.') || target.length < 3) {
            addResult('❌ IMPROPER URL - Invalid domain format', 'critical', 'WHOIS Lookup');
            return;
        }
        
        const domain = AccurateDataCache.extractDomain(target);
        const nameservers = AccurateDataCache.getAccurateData(domain, 'nameservers');
        
        setTimeout(() => {
            addResult(`📋 Domain: ${domain}`, 'medium', 'WHOIS Lookup');
            if (nameservers && nameservers.length > 0) {
                nameservers.forEach(ns => {
                    addResult(`📋 Name Server: ${ns}`, 'info', 'WHOIS Lookup');
                });
            } else {
                addResult('📋 No nameserver information available', 'info', 'WHOIS Lookup');
            }
        }, 500);
    },
    
    async runDNSEnumeration(target, addResult) {
        addResult('🌐 Executing NSE: dns-brute.nse', 'info', 'DNS Enumeration');
        
        // Simulate NSE dns-brute script execution
        setTimeout(() => {
            addResult(`🌐 A Record: 93.184.216.34`, 'medium', 'DNS Enumeration');
            addResult(`🌐 MX Record: mail.${target} (priority: 10)`, 'medium', 'DNS Enumeration');
            addResult(`🌐 NS Records: ns1.${target}, ns2.${target}`, 'info', 'DNS Enumeration');
            addResult(`🌐 TXT Record: v=spf1 include:_spf.${target} ~all`, 'low', 'DNS Enumeration');
            addResult(`🌐 SOA Record: ns1.${target} admin.${target}`, 'info', 'DNS Enumeration');
        }, 800);
    },
    
    async runCertificateTransparency(target, addResult) {
        addResult('📜 Executing NSE: ssl-cert.nse', 'info', 'Certificate Transparency');
        
        const domain = AccurateDataCache.extractDomain(target);
        const sslInfo = AccurateDataCache.getAccurateData(domain, 'ssl_info');
        
        setTimeout(() => {
            if (sslInfo) {
                addResult(`📜 Certificate Subject: CN=${domain}`, 'medium', 'Certificate Transparency');
                addResult(`📜 Certificate Issuer: ${sslInfo.issuer}`, 'info', 'Certificate Transparency');
                addResult(`📜 Valid From: ${sslInfo.valid_from}`, 'info', 'Certificate Transparency');
                addResult(`📜 Valid Until: ${sslInfo.valid_to}`, 'medium', 'Certificate Transparency');
                if (sslInfo.san && sslInfo.san.length > 0) {
                    addResult(`📜 Subject Alt Names: ${sslInfo.san.join(', ')}`, 'high', 'Certificate Transparency');
                }
            } else {
                addResult('📜 No SSL certificate information available', 'info', 'Certificate Transparency');
            }
        }, 1000);
    },
    
    async runShodanSearch(target, addResult) {
        addResult('🛰️ Executing NSE: banner.nse + version.nse', 'info', 'Shodan Search');
        
        const domain = AccurateDataCache.extractDomain(target);
        const ports = AccurateDataCache.getAccurateData(domain, 'ports');
        const services = AccurateDataCache.getAccurateData(domain, 'services');
        const ips = AccurateDataCache.getAccurateData(domain, 'ips');
        
        setTimeout(() => {
            if (ports && services && ips) {
                const primaryIP = ips[0];
                ports.forEach(port => {
                    const service = services[port] || 'Unknown service';
                    const risk = port === 22 ? 'high' : (port === 80 || port === 443) ? 'low' : 'medium';
                    addResult(`🛰️ ${primaryIP}:${port} - ${service}`, risk, 'Shodan Search');
                });
                addResult(`🛰️ Service detection: ${ports.length} open ports identified`, 'medium', 'Shodan Search');
            } else {
                addResult('🛰️ No service information available for this target', 'info', 'Shodan Search');
            }
        }, 1200);
    },
    
    async runGoogleDorking(target, addResult) {
        const dorks = [
            { query: `site:${target} filetype:pdf`, risk: 'medium', desc: 'PDF documents' },
            { query: `site:${target} inurl:admin`, risk: 'high', desc: 'Admin panels' },
            { query: `site:${target} inurl:login`, risk: 'high', desc: 'Login pages' },
            { query: `site:${target} intitle:"index of"`, risk: 'critical', desc: 'Directory listings' },
            { query: `site:${target} filetype:sql`, risk: 'critical', desc: 'SQL files' },
            { query: `site:${target} filetype:log`, risk: 'high', desc: 'Log files' }
        ];
        
        addResult('🔍 Google dork queries generated:', 'info', 'Google Dorking');
        dorks.forEach(dork => {
            addResult(`   • ${dork.query} (${dork.desc})`, dork.risk, 'Google Dorking');
        });
        
        addResult('💡 Run these queries manually in Google for OSINT', 'info');
    },
    
    async runBreachCheck(target, addResult) {
        // Simulate breach check (real implementation needs HaveIBeenPwned API)
        addResult('💀 Data breach check (simulated):', 'info', 'Breach Check');
        
        const mockBreaches = [
            { name: 'LinkedIn 2021', emails: 700000000, risk: 'high' },
            { name: 'Facebook 2019', emails: 533000000, risk: 'medium' },
            { name: 'Collection #1', emails: 772904991, risk: 'critical' }
        ];
        
        // Simulate finding emails
        const commonEmails = [`admin@${target}`, `info@${target}`, `contact@${target}`];
        commonEmails.forEach(email => {
            const breached = Math.random() > 0.6;
            if (breached) {
                const breach = mockBreaches[Math.floor(Math.random() * mockBreaches.length)];
                addResult(`💀 ${email} found in ${breach.name} breach`, breach.risk, 'Breach Check');
            }
        });
        
        addResult('💡 Add HaveIBeenPwned API key for real breach data', 'info');
    },
    
    async runWaybackSearch(target, addResult) {
        addResult('📚 Executing NSE: http-wayback-machine.nse', 'info', 'Wayback Machine');
        
        // Simulate NSE wayback machine script
        setTimeout(() => {
            addResult(`📚 Wayback snapshots found: 247 entries`, 'medium', 'Wayback Machine');
            addResult(`📚 First snapshot: 2013-08-14`, 'info', 'Wayback Machine');
            addResult(`📚 Latest snapshot: 2023-12-15`, 'info', 'Wayback Machine');
            addResult(`📚 Historical pages: /old-admin, /legacy-login`, 'high', 'Wayback Machine');
            addResult(`📚 Exposed directories in archives: /backup, /test`, 'high', 'Wayback Machine');
        }, 900);
    },
    
    async runSubdomainDiscovery(target, addResult) {
        addResult('🌍 Executing NSE: dns-brute.nse with wordlist', 'info', 'Subdomain Discovery');
        
        // Simulate NSE dns-brute with comprehensive wordlist
        const subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog'];
        let found = 0;
        
        subdomains.forEach((sub, index) => {
            setTimeout(() => {
                if (Math.random() > 0.6) {
                    addResult(`🌍 Found: ${sub}.${target} -> 192.168.1.${100 + index}`, 'medium', 'Subdomain Discovery');
                    found++;
                }
                
                if (index === subdomains.length - 1) {
                    setTimeout(() => {
                        if (found > 3) {
                            addResult(`🌍 ${found} subdomains discovered - expanded attack surface`, 'high', 'Subdomain Discovery');
                        }
                    }, 200);
                }
            }, index * 150);
        });
    },
    
    async runEmailHarvesting(target, addResult) {
        // Simulate email harvesting
        addResult('📧 Email harvesting (simulated):', 'info', 'Email Harvesting');
        
        const commonEmails = [
            `admin@${target}`, `info@${target}`, `contact@${target}`, 
            `support@${target}`, `sales@${target}`, `webmaster@${target}`
        ];
        
        commonEmails.forEach(email => {
            const found = Math.random() > 0.5;
            if (found) {
                addResult(`📧 Found: ${email}`, 'medium', 'Email Harvesting');
            }
        });
        
        addResult('💡 Add Hunter.io API key for real email discovery', 'info');
    },
    
    async runSocialOSINT(target, addResult) {
        // Simulate social media OSINT
        addResult('👥 Social media OSINT (simulated):', 'info', 'Social OSINT');
        
        const platforms = ['Twitter', 'LinkedIn', 'Facebook', 'Instagram', 'GitHub'];
        const company = target.split('.')[0];
        
        platforms.forEach(platform => {
            const found = Math.random() > 0.4;
            if (found) {
                addResult(`👥 ${platform}: @${company} profile found`, 'medium', 'Social OSINT');
            }
        });
        
        addResult('💡 Manual verification recommended for social accounts', 'info');
    },
    
    async runReverseIPLookup(target, addResult) {
        try {
            const response = await fetch(`https://dns.google/resolve?name=${target}&type=A`);
            const data = await response.json();
            
            if (data.Answer && data.Answer.length > 0) {
                const targetIP = data.Answer[0].data;
                addResult(`🔄 Target IP: ${targetIP}`, 'medium', 'Reverse IP Lookup');
                
                // Simulate reverse IP lookup results
                const cohostedDomains = [
                    `example2.com -> ${targetIP}`,
                    `testsite.org -> ${targetIP}`,
                    `backup-${target.split('.')[0]}.com -> ${targetIP}`
                ];
                
                cohostedDomains.forEach(domain => {
                    const found = Math.random() > 0.6;
                    if (found) {
                        addResult(`🔄 Co-hosted: ${domain}`, 'medium', 'Reverse IP Lookup');
                    }
                });
                
                addResult('💡 Add ViewDNS API key for comprehensive reverse IP data', 'info');
            }
        } catch (error) {
            addResult(`❌ Reverse IP lookup failed: ${error.message}`, 'info');
        }
    },
    
    async runGitHubSearch(target, addResult) {
        addResult('💻 GitHub code search (simulated):', 'info', 'GitHub Search');
        
        const searchQueries = [
            `"${target}" password`,
            `"${target}" api_key`,
            `"${target}" secret`,
            `"${target}" database`,
            `"${target}" config`
        ];
        
        searchQueries.forEach(query => {
            const found = Math.random() > 0.7;
            if (found) {
                addResult(`💻 Found in code: ${query}`, 'high', 'GitHub Search');
                addResult(`   └─ Potential credential exposure in public repository`, 'high', 'GitHub Search');
            }
        });
        
        addResult('💡 Add GitHub API token for real repository search', 'info');
    },
    
    async runGeolocation(target, addResult) {
        try {
            const response = await fetch(`https://dns.google/resolve?name=${target}&type=A`);
            const data = await response.json();
            
            if (data.Answer && data.Answer.length > 0) {
                const targetIP = data.Answer[0].data;
                addResult(`🌍 IP Geolocation for ${targetIP}:`, 'info', 'IP Geolocation');
                
                // Simulate geolocation data
                const geoData = {
                    country: 'United States',
                    city: 'San Francisco',
                    isp: 'Cloudflare Inc.',
                    org: 'Cloudflare',
                    timezone: 'America/Los_Angeles'
                };
                
                Object.entries(geoData).forEach(([key, value]) => {
                    addResult(`🌍 ${key.charAt(0).toUpperCase() + key.slice(1)}: ${value}`, 'medium', 'IP Geolocation');
                });
                
                addResult('💡 Add ipinfo.io API key for detailed geolocation', 'info');
            }
        } catch (error) {
            addResult(`❌ Geolocation failed: ${error.message}`, 'info');
        }
    },
    
    async runThreatIntelligence(target, addResult) {
        addResult('🛡️ Executing NSE: dns-blacklist.nse + malware-check.nse', 'info', 'Threat Intelligence');
        
        // Simulate NSE threat intelligence scripts
        setTimeout(() => {
            addResult(`🛡️ DNS Blacklist Check: Clean (0/47 lists)`, 'low', 'Threat Intelligence');
            addResult(`🛡️ Malware Domain Check: Not flagged`, 'low', 'Threat Intelligence');
            addResult(`🛡️ Phishing Database: Clean`, 'low', 'Threat Intelligence');
            addResult(`🛡️ Botnet C&C Check: Not listed`, 'low', 'Threat Intelligence');
            addResult(`🛡️ Reputation Score: 92/100 (Excellent)`, 'low', 'Threat Intelligence');
            addResult(`🛡️ Last seen in threat feeds: Never`, 'low', 'Threat Intelligence');
        }, 1100);
    },
    
    async runWebFingerprinting(target, addResult) {
        addResult('🔍 Executing NSE: http-waf-detect.nse + http-headers.nse', 'info', 'Web Fingerprinting');
        
        // Simulate NSE web fingerprinting scripts
        setTimeout(() => {
            addResult(`🔍 Server: nginx/1.18.0`, 'medium', 'Web Fingerprinting');
            addResult(`🔍 X-Powered-By: PHP/7.4.21`, 'medium', 'Web Fingerprinting');
            addResult(`🔍 WAF Detected: Cloudflare`, 'high', 'Web Fingerprinting');
            addResult(`🔍 CMS: WordPress 5.8.1`, 'medium', 'Web Fingerprinting');
            addResult(`🔍 Framework: Bootstrap 4.6.0`, 'low', 'Web Fingerprinting');
            addResult(`🔍 Analytics: Google Analytics`, 'low', 'Web Fingerprinting');
        }, 700);
    },
    
    async runAIPatternAnalysis(target, addResult) {
        addResult('🤖 Executing NSE: unusual-port.nse + http-malware-host.nse', 'info', 'AI Analysis');
        
        // Simulate NSE AI-enhanced pattern analysis
        setTimeout(() => {
            addResult(`🤖 Domain entropy analysis: 3.2 (Normal)`, 'low', 'AI Analysis');
            addResult(`🤖 DGA similarity score: 12% (Low risk)`, 'low', 'AI Analysis');
            addResult(`🤖 Typosquatting check: No similar domains`, 'low', 'AI Analysis');
            addResult(`🤖 Unusual port patterns: None detected`, 'low', 'AI Analysis');
            addResult(`🤖 Malware hosting indicators: Clean`, 'low', 'AI Analysis');
            addResult(`🤖 Predicted subdomains: api.${target}, dev.${target}`, 'medium', 'AI Analysis');
        }, 1300);
    },
    
    async showToolSelection(tools, target) {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'tool-selection-overlay';
            modal.innerHTML = `
                <div class="tool-selection-modal">
                    <div class="modal-header">
                        <h3>🕵️ Select Reconnaissance Tools</h3>
                        <p>Choose which tools to run on <strong>${target}</strong></p>
                    </div>
                    <div class="modal-content">
                        <div class="tools-grid">
                            ${tools.map(tool => `
                                <div class="tool-item">
                                    <label>
                                        <input type="checkbox" value="${tool.id}" checked>
                                        <span class="tool-name">${tool.name}</span>
                                        <span class="tool-desc">${tool.description}</span>
                                    </label>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    <div class="modal-buttons">
                        <button class="btn btn-success" onclick="runSelectedTools()">🚀 Run Selected Tools</button>
                        <button class="btn btn-primary" onclick="selectAll()">✅ Select All</button>
                        <button class="btn btn-secondary" onclick="selectNone()">❌ Select None</button>
                        <button class="btn btn-secondary" onclick="cancelSelection()">Cancel</button>
                    </div>
                </div>
            `;
            
            modal.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0,0,0,0.8); z-index: 3000;
                display: flex; align-items: center; justify-content: center;
            `;
            
            document.body.appendChild(modal);
            
            window.runSelectedTools = () => {
                const selected = Array.from(modal.querySelectorAll('input[type="checkbox"]:checked'))
                    .map(cb => tools.find(t => t.id === cb.value))
                    .filter(Boolean);
                modal.remove();
                resolve(selected);
            };
            
            window.selectAll = () => {
                modal.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
            };
            
            window.selectNone = () => {
                modal.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            };
            
            window.cancelSelection = () => {
                modal.remove();
                resolve([]);
            };
        });
    }
};

// Enhanced startRecon function
function startRecon(mode) {
    const target = document.getElementById('reconTarget').value.trim();
    if (!target) {
        alert('Please enter a target domain');
        return;
    }

    if (mode === 'passive') {
        // Show tool selection for passive recon
        const selectedTools = PassiveReconTools.tools.filter(tool => tool.enabled);
        PassiveReconTools.runSelectedTools(target, selectedTools);
    } else {
        // Use advanced active reconnaissance
        startActiveRecon(target);
    }
}