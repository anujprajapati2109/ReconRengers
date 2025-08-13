// Live OSINT Scanner - Only Real, Verifiable Data
const LiveOSINTScanner = {
    
    async executeLiveOSINT(target, addResult) {
        const domain = this.extractDomain(target);
        
        addResult('LIVE OSINT RECONNAISSANCE', 'info');
        addResult(`Target: ${domain}`, 'info');
        addResult(`Scan Time: ${new Date().toISOString()}`, 'info');
        addResult('=' .repeat(50), 'info');

        // Only run checks that return real data
        await this.liveDNSCheck(domain, addResult);
        await this.liveHTTPCheck(domain, addResult);
        await this.liveCertificateCheck(domain, addResult);
        await this.livePortCheck(domain, addResult);
        
        addResult('=' .repeat(50), 'info');
        addResult('OSINT SCAN COMPLETE', 'info');
        addResult('Note: Only live, verifiable data reported', 'info');
    },

    async liveDNSCheck(domain, addResult) {
        addResult('DNS RESOLUTION CHECK', 'info');
        
        try {
            // Real DNS lookup using browser DNS API
            const response = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
            const data = await response.json();
            
            if (data.Answer && data.Answer.length > 0) {
                data.Answer.forEach(record => {
                    addResult(`A Record: ${record.data}`, 'info');
                });
            } else {
                addResult('No A records found', 'info');
            }
        } catch (error) {
            addResult('DNS lookup failed - domain may not exist', 'info');
        }

        // MX Records
        try {
            const mxResponse = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
            const mxData = await mxResponse.json();
            
            if (mxData.Answer && mxData.Answer.length > 0) {
                mxData.Answer.forEach(record => {
                    addResult(`MX Record: ${record.data}`, 'info');
                });
            } else {
                addResult('No MX records found', 'info');
            }
        } catch (error) {
            addResult('MX lookup failed', 'info');
        }
    },

    async liveHTTPCheck(domain, addResult) {
        addResult('HTTP SERVICE CHECK', 'info');
        
        const protocols = ['http', 'https'];
        
        for (let protocol of protocols) {
            try {
                const testUrl = `${protocol}://${domain}`;
                const response = await fetch(testUrl, { 
                    method: 'HEAD',
                    mode: 'no-cors',
                    timeout: 5000 
                });
                
                addResult(`${protocol.toUpperCase()}: Service responding`, 'info');
            } catch (error) {
                addResult(`${protocol.toUpperCase()}: No response`, 'info');
            }
        }
    },

    async liveCertificateCheck(domain, addResult) {
        addResult('SSL CERTIFICATE CHECK', 'info');
        
        try {
            // Use crt.sh API for real certificate transparency data
            const response = await fetch(`https://crt.sh/?q=${domain}&output=json`);
            const certs = await response.json();
            
            if (certs && certs.length > 0) {
                // Get most recent certificate
                const recentCert = certs[0];
                addResult(`Certificate found: ${recentCert.name_value}`, 'info');
                addResult(`Issuer: ${recentCert.issuer_name}`, 'info');
                addResult(`Valid from: ${recentCert.not_before}`, 'info');
                addResult(`Valid until: ${recentCert.not_after}`, 'info');
                
                // Check for additional domains in certificate
                const altNames = recentCert.name_value.split('\n').filter(name => name !== domain);
                if (altNames.length > 0) {
                    addResult(`Additional domains in cert: ${altNames.length}`, 'medium');
                    altNames.slice(0, 3).forEach(name => {
                        addResult(`  ${name}`, 'info');
                    });
                }
            } else {
                addResult('No SSL certificates found in CT logs', 'info');
            }
        } catch (error) {
            addResult('Certificate transparency lookup failed', 'info');
        }
    },

    async livePortCheck(domain, addResult) {
        addResult('COMMON PORT CHECK', 'info');
        
        // Only check ports that can be verified via browser
        const commonPorts = [80, 443, 8080, 8443];
        
        for (let port of commonPorts) {
            try {
                const testUrl = port === 443 || port === 8443 ? 
                    `https://${domain}:${port}` : `http://${domain}:${port}`;
                
                const response = await fetch(testUrl, { 
                    method: 'HEAD',
                    mode: 'no-cors',
                    timeout: 3000 
                });
                
                addResult(`Port ${port}: Open`, 'info');
            } catch (error) {
                addResult(`Port ${port}: Closed/Filtered`, 'info');
            }
        }
    },

    // Real subdomain enumeration using certificate transparency
    async realSubdomainEnum(domain, addResult) {
        addResult('SUBDOMAIN ENUMERATION (CT Logs)', 'info');
        
        try {
            const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
            const certs = await response.json();
            
            if (certs && certs.length > 0) {
                const subdomains = new Set();
                
                certs.forEach(cert => {
                    const names = cert.name_value.split('\n');
                    names.forEach(name => {
                        if (name.includes(domain) && name !== domain) {
                            subdomains.add(name);
                        }
                    });
                });
                
                if (subdomains.size > 0) {
                    addResult(`Subdomains found: ${subdomains.size}`, 'medium');
                    Array.from(subdomains).slice(0, 10).forEach(sub => {
                        addResult(`  ${sub}`, 'info');
                    });
                    
                    if (subdomains.size > 10) {
                        addResult(`  ... and ${subdomains.size - 10} more`, 'info');
                    }
                } else {
                    addResult('No subdomains found in CT logs', 'info');
                }
            } else {
                addResult('No certificate data available', 'info');
            }
        } catch (error) {
            addResult('Subdomain enumeration failed', 'info');
        }
    },

    // Real GitHub search (limited by CORS, but shows concept)
    async realGitHubSearch(domain, addResult) {
        addResult('GITHUB CODE SEARCH', 'info');
        
        // Note: Real implementation would need GitHub API token
        // This shows the concept but is limited by CORS
        addResult('GitHub search requires API authentication', 'info');
        addResult('Manual search recommended:', 'info');
        addResult(`  https://github.com/search?q="${domain}"`, 'info');
        addResult(`  https://github.com/search?q="${domain}"+password`, 'info');
        addResult(`  https://github.com/search?q="${domain}"+api_key`, 'info');
    },

    // Real breach data check
    async realBreachCheck(domain, addResult) {
        addResult('BREACH DATA CHECK', 'info');
        
        // Note: Real implementation would use HaveIBeenPwned API
        addResult('Breach check requires HaveIBeenPwned API key', 'info');
        addResult('Manual check recommended:', 'info');
        addResult(`  https://haveibeenpwned.com/domain-search`, 'info');
        
        // Common email patterns to check manually
        const commonEmails = [`admin@${domain}`, `info@${domain}`, `contact@${domain}`];
        addResult('Common email patterns to check:', 'info');
        commonEmails.forEach(email => {
            addResult(`  ${email}`, 'info');
        });
    },

    extractDomain(target) {
        try {
            return new URL(target).hostname.replace('www.', '');
        } catch {
            return target.replace('www.', '');
        }
    }
};

window.LiveOSINTScanner = LiveOSINTScanner;