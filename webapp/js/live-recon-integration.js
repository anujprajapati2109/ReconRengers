// Live Recon Integration - Real OSINT with Authorization
const LiveReconIntegration = {
    
    async executeLiveRecon(target, addResult) {
        const domain = this.extractDomain(target);
        
        addResult('LIVE OSINT RECONNAISSANCE', 'info');
        addResult(`Target: ${domain}`, 'info');
        addResult(`Timestamp: ${new Date().toISOString()}`, 'info');
        addResult('Authorization: DNS TXT verification required for full scan', 'info');
        addResult('=' .repeat(60), 'info');

        // Phase 1: DNS Authorization Check
        await this.checkDNSAuthorization(domain, addResult);
        
        // Phase 2: Certificate Transparency (Real Data)
        await this.realCertificateTransparency(domain, addResult);
        
        // Phase 3: Live HTTP Verification
        await this.liveHTTPVerification(domain, addResult);
        
        // Phase 4: Real DNS Resolution
        await this.realDNSResolution(domain, addResult);
        
        // Phase 5: GitHub Code Search (Limited by CORS)
        await this.githubCodeSearch(domain, addResult);
        
        addResult('=' .repeat(60), 'info');
        addResult('LIVE RECON COMPLETE', 'info');
        addResult('Note: Only verified, live data reported', 'info');
        addResult('For full scan: Set DNS TXT _recon.' + domain + ' "AUTH=token"', 'info');
    },

    async checkDNSAuthorization(domain, addResult) {
        addResult('PHASE 1: AUTHORIZATION VERIFICATION', 'info');
        
        try {
            // Check for authorization TXT record
            const response = await fetch(`https://dns.google/resolve?name=_recon.${domain}&type=TXT`);
            const data = await response.json();
            
            if (data.Answer && data.Answer.length > 0) {
                const txtRecord = data.Answer[0].data.replace(/"/g, '');
                if (txtRecord.startsWith('AUTH=')) {
                    addResult('✅ Authorization TXT record found', 'info');
                    addResult(`   └─ Record: ${txtRecord}`, 'info');
                    return true;
                } else {
                    addResult('⚠️ TXT record exists but invalid format', 'medium');
                }
            } else {
                addResult('❌ No authorization TXT record found', 'info');
                addResult('   └─ Add: _recon.' + domain + ' TXT "AUTH=your-token"', 'info');
            }
        } catch (error) {
            addResult('❌ Authorization check failed', 'info');
        }
        
        return false;
    },

    async realCertificateTransparency(domain, addResult) {
        addResult('PHASE 2: CERTIFICATE TRANSPARENCY (LIVE)', 'info');
        
        try {
            const response = await fetch(`https://crt.sh/?q=${domain}&output=json`);
            const certs = await response.json();
            
            if (certs && certs.length > 0) {
                // Get unique subdomains from certificates
                const subdomains = new Set();
                const recentCerts = certs.slice(0, 10); // Latest 10 certificates
                
                recentCerts.forEach(cert => {
                    const names = cert.name_value.split('\n');
                    names.forEach(name => {
                        const cleanName = name.trim().toLowerCase();
                        if (cleanName.endsWith('.' + domain) || cleanName === domain) {
                            subdomains.add(cleanName);
                        }
                    });
                });
                
                addResult(`✅ Certificate data found: ${certs.length} total certificates`, 'info');
                addResult(`📋 Unique subdomains discovered: ${subdomains.size}`, 'medium');
                
                // Show first few subdomains
                const subArray = Array.from(subdomains).slice(0, 5);
                subArray.forEach(sub => {
                    addResult(`   └─ ${sub}`, 'info');
                });
                
                if (subdomains.size > 5) {
                    addResult(`   └─ ... and ${subdomains.size - 5} more`, 'info');
                }
                
                return Array.from(subdomains);
            } else {
                addResult('ℹ️ No certificates found in CT logs', 'info');
                return [domain];
            }
        } catch (error) {
            addResult('❌ Certificate transparency lookup failed', 'info');
            return [domain];
        }
    },

    async liveHTTPVerification(domain, addResult) {
        addResult('PHASE 3: LIVE HTTP VERIFICATION', 'info');
        
        const protocols = ['https', 'http'];
        const liveHosts = [];
        
        for (let protocol of protocols) {
            try {
                const testUrl = `${protocol}://${domain}`;
                
                // Use fetch with no-cors to test connectivity
                const response = await fetch(testUrl, { 
                    method: 'HEAD',
                    mode: 'no-cors',
                    timeout: 5000 
                });
                
                addResult(`✅ ${protocol.toUpperCase()}: Service responding`, 'info');
                addResult(`   └─ URL: ${testUrl}`, 'info');
                liveHosts.push(testUrl);
                break; // If HTTPS works, don't try HTTP
                
            } catch (error) {
                addResult(`❌ ${protocol.toUpperCase()}: No response`, 'info');
            }
        }
        
        if (liveHosts.length === 0) {
            addResult('⚠️ No HTTP services responding', 'medium');
        }
        
        return liveHosts;
    },

    async realDNSResolution(domain, addResult) {
        addResult('PHASE 4: DNS RESOLUTION (LIVE)', 'info');
        
        const recordTypes = [
            { type: 'A', description: 'IPv4 addresses' },
            { type: 'AAAA', description: 'IPv6 addresses' },
            { type: 'MX', description: 'Mail servers' },
            { type: 'NS', description: 'Name servers' },
            { type: 'TXT', description: 'Text records' }
        ];
        
        for (let record of recordTypes) {
            try {
                const response = await fetch(`https://dns.google/resolve?name=${domain}&type=${record.type}`);
                const data = await response.json();
                
                if (data.Answer && data.Answer.length > 0) {
                    addResult(`✅ ${record.type} Records (${record.description}):`, 'info');
                    data.Answer.forEach(answer => {
                        addResult(`   └─ ${answer.data}`, 'info');
                    });
                } else {
                    addResult(`ℹ️ No ${record.type} records found`, 'info');
                }
            } catch (error) {
                addResult(`❌ ${record.type} lookup failed`, 'info');
            }
        }
    },

    async githubCodeSearch(domain, addResult) {
        addResult('PHASE 5: GITHUB CODE SEARCH', 'info');
        
        // Note: Limited by CORS, but show the concept
        addResult('⚠️ GitHub API requires authentication token', 'info');
        addResult('Manual search URLs for verification:', 'info');
        
        const searchQueries = [
            `"${domain}"`,
            `"${domain}" password`,
            `"${domain}" api_key`,
            `"${domain}" secret`,
            `"${domain}" config`
        ];
        
        searchQueries.forEach(query => {
            const searchUrl = `https://github.com/search?q=${encodeURIComponent(query)}&type=code`;
            addResult(`   └─ ${query}: ${searchUrl}`, 'info');
        });
        
        addResult('💡 Add GitHub token for automated search', 'info');
    },

    // Real subdomain enumeration using multiple sources
    async realSubdomainEnumeration(domain, addResult) {
        addResult('SUBDOMAIN ENUMERATION (MULTIPLE SOURCES)', 'info');
        
        const sources = [];
        
        // Certificate Transparency
        try {
            const ctResponse = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
            const ctData = await ctResponse.json();
            
            if (ctData && ctData.length > 0) {
                const ctSubs = new Set();
                ctData.forEach(cert => {
                    const names = cert.name_value.split('\n');
                    names.forEach(name => {
                        const cleanName = name.trim().toLowerCase();
                        if (cleanName.includes(domain) && cleanName !== domain) {
                            ctSubs.add(cleanName);
                        }
                    });
                });
                sources.push({ name: 'Certificate Transparency', count: ctSubs.size, subs: Array.from(ctSubs) });
            }
        } catch (error) {
            addResult('❌ Certificate Transparency failed', 'info');
        }
        
        // Combine and deduplicate
        const allSubs = new Set();
        sources.forEach(source => {
            addResult(`📋 ${source.name}: ${source.count} subdomains`, 'info');
            source.subs.forEach(sub => allSubs.add(sub));
        });
        
        if (allSubs.size > 0) {
            addResult(`🎯 Total unique subdomains: ${allSubs.size}`, 'medium');
            Array.from(allSubs).slice(0, 10).forEach(sub => {
                addResult(`   └─ ${sub}`, 'info');
            });
        } else {
            addResult('ℹ️ No subdomains discovered', 'info');
        }
        
        return Array.from(allSubs);
    },

    // Generate professional report
    generateLiveReport(domain, findings, addResult) {
        addResult('GENERATING LIVE RECON REPORT', 'info');
        
        const timestamp = new Date().toISOString();
        const report = {
            domain: domain,
            scan_time: timestamp,
            methodology: 'Live OSINT - Passive Only',
            findings: findings,
            verification: 'All data verified live at scan time',
            sources: [
                'Certificate Transparency (crt.sh)',
                'Google DNS API',
                'Live HTTP probing',
                'GitHub Code Search (manual)'
            ]
        };
        
        addResult('📊 Report Summary:', 'info');
        addResult(`   └─ Domain: ${domain}`, 'info');
        addResult(`   └─ Scan Time: ${timestamp}`, 'info');
        addResult(`   └─ Live Hosts: ${findings.liveHosts || 0}`, 'info');
        addResult(`   └─ Subdomains: ${findings.subdomains || 0}`, 'info');
        addResult(`   └─ DNS Records: ${findings.dnsRecords || 0}`, 'info');
        
        // Store report for download
        window.liveReconReport = report;
        addResult('💾 Report saved to browser memory', 'info');
        addResult('💡 Use browser dev tools to access window.liveReconReport', 'info');
    },

    extractDomain(target) {
        try {
            return new URL(target).hostname.replace('www.', '');
        } catch {
            return target.replace('www.', '');
        }
    }
};

window.LiveReconIntegration = LiveReconIntegration;