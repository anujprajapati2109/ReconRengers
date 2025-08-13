// Attack Summary System for Non-Technical Explanations

function showAttackSummary(attackType, attackData) {
    const attackResults = {
        type: attackType === 'bruteforce' ? 'Credential Attack Chain' : 
              attackType === 'xss' ? 'XSS Payload Testing' : 
              attackType === 'dos' ? 'Multi-Vector DDoS' : attackType,
        severity: attackData.severity,
        impact: attackData.details,
        compromised: attackData.success ? 1 : 0
    };
    
    window.lastAttackResults = attackResults;
    
function showAttackSummaryPopup(attackResults) {
    const nonTechExplanation = generateNonTechExplanation(attackResults);
    const immediateMeasures = getImmediateMeasures(attackResults);
    
    const content = `
        <div class="attack-summary">
            <h3>🎯 Attack Summary</h3>
            <div class="non-tech-explanation">
                <h4>📋 What We Found (In Simple Terms):</h4>
                <p>${nonTechExplanation}</p>
            </div>
            
            <div class="technical-details">
                <h4>🔍 Technical Details:</h4>
                <p><strong>Attack Type:</strong> ${attackResults.type}</p>
                <p><strong>Severity Level:</strong> <span class="severity-${attackResults.severity.toLowerCase()}">${attackResults.severity}</span></p>
                <p><strong>Impact:</strong> ${attackResults.impact}</p>
                ${attackResults.compromised ? `<p><strong>Accounts Affected:</strong> ${attackResults.compromised}</p>` : ''}
            </div>
            
            <div class="immediate-measures">
                <h4>🚨 Immediate Actions Required:</h4>
                <ul>
                    ${immediateMeasures.map(measure => `<li>${measure}</li>`).join('')}
                </ul>
            </div>
        </div>
    `;
    
    showAdvancedPopup('Attack Assessment Complete', content, 'warning', [
        { text: '📊 Generate Report', class: 'btn-primary', action: 'generateAttackReport(); closeAdvancedPopup(this);' },
        { text: '🛡️ Security Report', class: 'btn-danger', action: 'generateSecurityReport(); closeAdvancedPopup(this);' },
        { text: '📄 Download PDF', class: 'btn-success', action: 'downloadAttackPDF(); closeAdvancedPopup(this);' }
    ]);
}

function generateNonTechExplanation(attackResults) {
    const explanations = {
        'Credential Attack Chain': {
            'Critical': 'We successfully broke into your system by guessing passwords and then gained complete control. This is like someone figuring out your house key, getting inside, and then finding the master keys to every room. An attacker could steal all your data, delete files, or use your system to attack others.',
            'High': 'We broke into an admin account on your system but couldn\'t get complete control due to security measures. This is like someone getting into your office but being stopped by additional locks on important rooms. They could still cause significant damage to the areas they can access.',
            'Medium': 'We found valid passwords but additional security stopped us from logging in. This is like having the right key but finding out you also need a security code. While we couldn\'t get in this time, having the password is still dangerous.'
        },
        'Multi-Vector DDoS': {
            'Critical': 'We overwhelmed your website with so much fake traffic that it crashed and became unavailable to real users. This is like blocking all the roads to your store so customers can\'t reach you. Your business would lose money and customers would go elsewhere.',
            'High': 'We significantly slowed down your website with heavy traffic, making it very difficult for users to access. This is like creating traffic jams on roads to your store - some customers might get through but many will give up and leave.',
            'Medium': 'We attempted to overload your website but your protection systems mostly blocked our attack. This is like trying to create traffic jams but having good traffic management that keeps most roads clear.'
        },
        'XSS Payload Testing': {
            'Critical': 'We successfully injected malicious code into your website that could steal user information or take control of their accounts. This is like placing hidden cameras in your store that record customer credit card information without them knowing.',
            'High': 'We found ways to inject some malicious code but security measures limited what we could do. This is like being able to place some hidden devices but having security systems that detect and block the most dangerous ones.',
            'Medium': 'We tried to inject malicious code but your website\'s security successfully blocked our attempts. This is like trying to place hidden devices but having good security that catches and removes them.'
        }
    };
    
    return explanations[attackResults.type]?.[attackResults.severity] || 
           `We conducted a ${attackResults.type} and achieved ${attackResults.severity.toLowerCase()} level access to your system.`;
}

function getImmediateMeasures(attackResults) {
    const measures = {
        'Credential Attack Chain': {
            'Critical': [
                'Change all admin passwords immediately',
                'Enable two-factor authentication (2FA) on all accounts',
                'Check system logs for unauthorized activities',
                'Scan for malware and unauthorized software',
                'Review and revoke any suspicious user permissions',
                'Implement account lockout policies',
                'Set up monitoring for unusual login attempts'
            ],
            'High': [
                'Change compromised account passwords immediately',
                'Enable two-factor authentication (2FA)',
                'Review admin panel access logs',
                'Implement additional authentication layers',
                'Set up alerts for admin account usage',
                'Review and limit admin privileges'
            ],
            'Medium': [
                'Change all passwords that may have been compromised',
                'Enable two-factor authentication (2FA)',
                'Implement account lockout after failed attempts',
                'Set up monitoring for brute force attacks',
                'Review password policies and strengthen them'
            ]
        },
        'Multi-Vector DDoS': {
            'Critical': [
                'Contact your hosting provider immediately',
                'Implement DDoS protection service (Cloudflare, etc.)',
                'Set up traffic filtering and rate limiting',
                'Prepare backup servers or CDN',
                'Create incident response plan',
                'Monitor traffic patterns continuously'
            ],
            'High': [
                'Implement rate limiting on your servers',
                'Set up DDoS protection service',
                'Monitor server performance closely',
                'Prepare scaling solutions',
                'Review traffic filtering rules'
            ],
            'Medium': [
                'Review current DDoS protection effectiveness',
                'Consider upgrading protection services',
                'Monitor traffic patterns for future attacks',
                'Test server capacity limits'
            ]
        },
        'XSS Payload Testing': {
            'Critical': [
                'Immediately implement Content Security Policy (CSP)',
                'Sanitize all user inputs on your website',
                'Update your website framework to latest version',
                'Scan for existing malicious code',
                'Review all user-generated content',
                'Implement input validation on all forms',
                'Set up web application firewall (WAF)'
            ],
            'High': [
                'Strengthen input validation and sanitization',
                'Implement Content Security Policy (CSP)',
                'Review and update security headers',
                'Scan website for vulnerabilities',
                'Update web application frameworks'
            ],
            'Medium': [
                'Continue monitoring for XSS attempts',
                'Review and strengthen existing protections',
                'Regular security testing of web applications',
                'Keep security measures updated'
            ]
        }
    };
    
    return measures[attackResults.type]?.[attackResults.severity] || [
        'Review security logs for any suspicious activity',
        'Update all software and security patches',
        'Implement additional monitoring',
        'Consider professional security assessment'
    ];
}

function generateAttackReport() {
    const results = window.lastAttackResults;
    if (!results) {
        showAlert('No attack data available', 'error');
        return;
    }
    
    const target = document.getElementById('attackTarget')?.value || 'Unknown';
    const nonTechExplanation = generateNonTechExplanation(results);
    const measures = getImmediateMeasures(results);
    
    let report = `ANUJSCAN PRO - ATTACK ASSESSMENT REPORT\n${'='.repeat(50)}\n\n`;
    report += `Target: ${target}\n`;
    report += `Assessment Date: ${new Date().toLocaleString()}\n`;
    report += `Attack Type: ${results.type}\n`;
    report += `Severity Level: ${results.severity}\n\n`;
    
    report += `EXECUTIVE SUMMARY:\n${'='.repeat(20)}\n`;
    report += `${nonTechExplanation}\n\n`;
    
    report += `TECHNICAL DETAILS:\n${'='.repeat(18)}\n`;
    report += `Impact: ${results.impact}\n`;
    if (results.compromised) {
        report += `Accounts Affected: ${results.compromised}\n`;
    }
    report += `\n`;
    
    report += `IMMEDIATE ACTIONS REQUIRED:\n${'='.repeat(30)}\n`;
    measures.forEach((measure, i) => {
        report += `${i+1}. ${measure}\n`;
    });
    
    report += `\nGenerated by AnujScan Pro Attack Assessment Suite\n`;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attack-report-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    showAlert('📊 Attack report downloaded!', 'success');
}

function generateSecurityReport() {
    const results = window.lastAttackResults;
    if (!results) {
        showAlert('No attack data available', 'error');
        return;
    }
    
    const target = document.getElementById('attackTarget')?.value || 'Unknown';
    const measures = getImmediateMeasures(results);
    
    let report = `ANUJSCAN PRO - SECURITY REMEDIATION REPORT\n${'='.repeat(50)}\n\n`;
    report += `Target: ${target}\n`;
    report += `Assessment Date: ${new Date().toLocaleString()}\n`;
    report += `Threat Level: ${results.severity}\n`;
    report += `Attack Vector: ${results.type}\n\n`;
    
    report += `SECURITY GAPS IDENTIFIED:\n${'='.repeat(30)}\n`;
    report += `• Successful ${results.type} demonstrates security weaknesses\n`;
    report += `• ${results.impact}\n`;
    if (results.compromised) {
        report += `• ${results.compromised} accounts potentially compromised\n`;
    }
    report += `\n`;
    
    report += `IMMEDIATE REMEDIATION STEPS:\n${'='.repeat(32)}\n`;
    report += `Priority: URGENT - Implement within 24-48 hours\n\n`;
    measures.forEach((measure, i) => {
        report += `${i+1}. ${measure}\n`;
    });
    
    report += `\nLONG-TERM SECURITY IMPROVEMENTS:\n${'='.repeat(35)}\n`;
    report += `• Regular security assessments and penetration testing\n`;
    report += `• Employee security awareness training\n`;
    report += `• Implement security incident response plan\n`;
    report += `• Regular security updates and patch management\n`;
    report += `• Consider hiring dedicated security personnel\n`;
    
    report += `\nGenerated by AnujScan Pro Security Assessment Suite\n`;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-remediation-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    showAlert('🛡️ Security report downloaded!', 'success');
}

function downloadAttackPDF() {
    const results = window.lastAttackResults;
    if (!results) {
        showAlert('No attack data available', 'error');
        return;
    }
    
    try {
        const doc = new window.jspdf.jsPDF();
        const target = document.getElementById('attackTarget')?.value || 'Unknown';
        
        doc.setFontSize(16);
        doc.text('ANUJSCAN PRO - ATTACK ASSESSMENT', 20, 20);
        doc.setFontSize(12);
        doc.text(`Target: ${target}`, 20, 35);
        doc.text(`Date: ${new Date().toLocaleString()}`, 20, 45);
        doc.text(`Severity: ${results.severity}`, 20, 55);
        
        doc.text('EXECUTIVE SUMMARY:', 20, 75);
        const explanation = generateNonTechExplanation(results);
        const lines = doc.splitTextToSize(explanation, 170);
        doc.text(lines, 20, 85);
        
        let yPos = 85 + (lines.length * 5) + 10;
        doc.text('IMMEDIATE ACTIONS:', 20, yPos);
        yPos += 10;
        
        const measures = getImmediateMeasures(results);
        measures.slice(0, 5).forEach((measure, i) => {
            doc.text(`${i+1}. ${measure.substring(0, 60)}`, 25, yPos);
            yPos += 8;
        });
        
        doc.save(`attack-assessment-${new Date().toISOString().split('T')[0]}.pdf`);
        showAlert('📄 PDF report downloaded!', 'success');
    } catch (error) {
        console.error('PDF Error:', error);
        showAlert('PDF generation failed - downloading TXT instead', 'warning');
        generateAttackReport();
    }
}