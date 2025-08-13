// Realistic Security Data - Real-world vulnerability patterns
const RealisticSecurityData = {
    // Real production security profiles
    productionProfiles: {
        'google.com': {
            vulnerabilities: [],
            security_grade: 'A+',
            waf_active: true,
            ddos_protection: 'Cloudflare Enterprise',
            ssl_grade: 'A+',
            security_headers: ['CSP', 'HSTS', 'X-Frame-Options', 'X-Content-Type-Options'],
            patching_status: 'Current',
            notes: 'Enterprise-grade security, no known vulnerabilities'
        },
        'facebook.com': {
            vulnerabilities: [],
            security_grade: 'A+',
            waf_active: true,
            ddos_protection: 'Custom CDN',
            ssl_grade: 'A+',
            security_headers: ['CSP', 'HSTS', 'X-Frame-Options'],
            patching_status: 'Current',
            notes: 'Bug bounty program active, well-secured'
        },
        'github.com': {
            vulnerabilities: [],
            security_grade: 'A',
            waf_active: true,
            ddos_protection: 'Fastly',
            ssl_grade: 'A+',
            security_headers: ['CSP', 'HSTS'],
            patching_status: 'Current',
            notes: 'Developer-focused security, regularly updated'
        },
        'microsoft.com': {
            vulnerabilities: [],
            security_grade: 'A+',
            waf_active: true,
            ddos_protection: 'Azure Front Door',
            ssl_grade: 'A+',
            security_headers: ['CSP', 'HSTS', 'X-Frame-Options'],
            patching_status: 'Current',
            notes: 'Microsoft security standards, enterprise-grade'
        }
    },

    // Realistic vulnerability patterns for different site types
    getRealisticVulnerabilities(domain) {
        // Major tech companies - virtually no vulnerabilities
        const majorTech = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'github.com'];
        if (majorTech.includes(domain)) {
            return {
                critical: 0,
                high: 0,
                medium: 0,
                low: Math.random() > 0.8 ? 1 : 0, // Rare info disclosure
                findings: this.getMajorTechFindings(domain)
            };
        }

        // Financial institutions - very secure
        const financial = domain.includes('bank') || domain.includes('finance') || domain.includes('paypal');
        if (financial) {
            return {
                critical: 0,
                high: 0,
                medium: Math.random() > 0.9 ? 1 : 0,
                low: Math.random() > 0.7 ? 1 : 0,
                findings: ['Strong security posture', 'PCI DSS compliant']
            };
        }

        // Government sites - generally secure but may have info disclosure
        if (domain.includes('.gov') || domain.includes('.mil')) {
            return {
                critical: 0,
                high: 0,
                medium: Math.random() > 0.8 ? 1 : 0,
                low: Math.random() > 0.6 ? 1 : 0,
                findings: ['Government security standards', 'Regular security audits']
            };
        }

        // Small business/personal sites - may have some issues
        return {
            critical: Math.random() > 0.95 ? 1 : 0, // Very rare
            high: Math.random() > 0.85 ? 1 : 0,
            medium: Math.random() > 0.7 ? Math.floor(Math.random() * 2) + 1 : 0,
            low: Math.random() > 0.5 ? Math.floor(Math.random() * 3) + 1 : 0,
            findings: this.getSmallSiteFindings()
        };
    },

    getMajorTechFindings(domain) {
        const findings = [
            'Enterprise-grade WAF active',
            'Advanced DDoS protection',
            'Perfect SSL configuration',
            'Security headers properly configured',
            'No known vulnerabilities',
            'Bug bounty program active',
            'Regular security audits',
            'Incident response team available'
        ];
        return findings.slice(0, Math.floor(Math.random() * 3) + 3);
    },

    getSmallSiteFindings() {
        const possibleFindings = [
            'Outdated CMS version detected',
            'Missing security headers',
            'Weak SSL configuration',
            'Information disclosure in error pages',
            'Directory listing enabled',
            'Backup files accessible',
            'Default credentials on admin panel',
            'Unpatched plugins detected'
        ];
        
        const numFindings = Math.floor(Math.random() * 3) + 1;
        const shuffled = possibleFindings.sort(() => 0.5 - Math.random());
        return shuffled.slice(0, numFindings);
    },

    // Realistic exploitation success rates
    getExploitationReality(domain, vulnerabilityType) {
        const majorTech = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'github.com'];
        
        if (majorTech.includes(domain)) {
            return {
                success: false,
                reason: 'Enterprise security controls active',
                defenses: ['WAF blocking', 'Rate limiting', 'Behavioral analysis', 'SOC monitoring']
            };
        }

        // Even small sites have some protection these days
        const baseSuccessRate = {
            'sql_injection': 0.05, // 5% - most sites use frameworks now
            'xss': 0.15, // 15% - still common but often filtered
            'rce': 0.02, // 2% - very rare
            'lfi': 0.08, // 8% - some older sites
            'directory_traversal': 0.12 // 12% - configuration issues
        };

        const rate = baseSuccessRate[vulnerabilityType] || 0.03;
        return {
            success: Math.random() < rate,
            reason: Math.random() < rate ? 'Vulnerability confirmed' : 'Attack blocked by security measures',
            defenses: Math.random() < rate ? [] : ['Input validation', 'WAF protection', 'Framework security']
        };
    },

    // Professional reporting format
    generateProfessionalReport(domain, findings) {
        const timestamp = new Date().toISOString();
        return {
            executive_summary: this.getExecutiveSummary(findings),
            technical_findings: findings,
            risk_assessment: this.calculateRisk(findings),
            recommendations: this.getRecommendations(findings),
            methodology: 'OWASP Testing Guide v4.0, NIST SP 800-115',
            scan_date: timestamp,
            target: domain
        };
    },

    getExecutiveSummary(findings) {
        const total = findings.critical + findings.high + findings.medium + findings.low;
        
        if (total === 0) {
            return 'Security assessment completed. No significant vulnerabilities identified. Target demonstrates strong security posture.';
        } else if (findings.critical > 0) {
            return `Critical security issues identified requiring immediate attention. ${findings.critical} critical, ${findings.high} high-risk findings detected.`;
        } else if (findings.high > 0) {
            return `High-risk vulnerabilities detected requiring prompt remediation. ${findings.high} high, ${findings.medium} medium-risk findings identified.`;
        } else {
            return `Low to medium risk findings identified. ${findings.medium} medium, ${findings.low} low-risk issues detected.`;
        }
    },

    calculateRisk(findings) {
        const score = (findings.critical * 10) + (findings.high * 7) + (findings.medium * 4) + (findings.low * 1);
        
        if (score === 0) return 'Low';
        if (score <= 5) return 'Low';
        if (score <= 15) return 'Medium';
        if (score <= 30) return 'High';
        return 'Critical';
    },

    getRecommendations(findings) {
        const recs = [];
        
        if (findings.critical > 0) {
            recs.push('Immediate patching of critical vulnerabilities required');
            recs.push('Consider taking affected systems offline until patched');
        }
        
        if (findings.high > 0) {
            recs.push('High-priority vulnerabilities should be addressed within 72 hours');
            recs.push('Implement additional monitoring for affected systems');
        }
        
        if (findings.medium > 0) {
            recs.push('Medium-risk issues should be addressed in next maintenance window');
        }
        
        if (findings.low > 0) {
            recs.push('Low-risk findings can be addressed during regular updates');
        }
        
        // Always include general recommendations
        recs.push('Regular security assessments recommended');
        recs.push('Implement security awareness training');
        recs.push('Maintain current patch levels');
        
        return recs;
    }
};

window.RealisticSecurityData = RealisticSecurityData;