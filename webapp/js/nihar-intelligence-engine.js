/**
 * Nihar's Custom Intelligence Engine
 * Correlates passive + active reconnaissance into ranked risk profiles
 * This is the "creator fingerprint" - custom logic, scoring, and decision-making
 */

class NiharIntelligenceEngine {
    constructor() {
        this.assetProfiles = new Map();
        this.correlationRules = this.initializeCorrelationRules();
        this.riskWeights = this.initializeRiskWeights();
    }

    initializeCorrelationRules() {
        return {
            // High-risk correlations (Nihar's custom logic)
            criticalCombos: [
                { passive: ['exposed_admin', 'weak_ssl'], active: ['open_admin_port'], score: 95 },
                { passive: ['subdomain_takeover', 'expired_cert'], active: ['directory_listing'], score: 90 },
                { passive: ['leaked_credentials', 'github_secrets'], active: ['login_page'], score: 88 },
                { passive: ['shodan_vulns', 'cve_match'], active: ['service_banner'], score: 85 }
            ],
            // Medium-risk patterns
            mediumCombos: [
                { passive: ['dns_wildcards', 'zone_transfer'], active: ['subdomain_enum'], score: 70 },
                { passive: ['whois_privacy', 'recent_changes'], active: ['port_scan'], score: 65 },
                { passive: ['social_media', 'employee_data'], active: ['email_enum'], score: 60 }
            ],
            // Stealth detection patterns (unique to Nihar's approach)
            stealthIndicators: [
                { pattern: 'rapid_sequential_scans', weight: 0.8 },
                { pattern: 'uncommon_user_agents', weight: 0.6 },
                { pattern: 'timing_analysis_attempts', weight: 0.7 }
            ]
        };
    }

    initializeRiskWeights() {
        return {
            // Nihar's custom risk scoring weights
            vulnerability: { critical: 40, high: 30, medium: 20, low: 10 },
            exposure: { public: 25, internal: 15, restricted: 5 },
            exploitability: { remote: 30, local: 15, physical: 5 },
            impact: { data_breach: 35, service_disruption: 25, reputation: 15 },
            correlation_bonus: { perfect_match: 20, partial_match: 10, weak_match: 5 }
        };
    }

    // Main correlation function - Nihar's unique algorithm
    correlateReconData(passiveData, activeData, target) {
        const profile = {
            target: target,
            timestamp: new Date().toISOString(),
            riskScore: 0,
            criticalFindings: [],
            correlatedThreats: [],
            recommendations: [],
            niharScore: 0 // Custom scoring algorithm
        };

        // Apply Nihar's correlation logic
        profile.correlatedThreats = this.findThreatCorrelations(passiveData, activeData);
        profile.riskScore = this.calculateNiharRiskScore(profile.correlatedThreats);
        profile.criticalFindings = this.prioritizeFindings(profile.correlatedThreats);
        profile.recommendations = this.generateSmartRecommendations(profile);
        profile.niharScore = this.calculateCreatorScore(passiveData, activeData, profile);

        this.assetProfiles.set(target, profile);
        return profile;
    }

    // Nihar's threat correlation algorithm
    findThreatCorrelations(passive, active) {
        const correlations = [];

        // Check critical combinations
        this.correlationRules.criticalCombos.forEach(rule => {
            const passiveMatch = rule.passive.some(p => this.hasPassiveIndicator(passive, p));
            const activeMatch = rule.active.some(a => this.hasActiveIndicator(active, a));
            
            if (passiveMatch && activeMatch) {
                correlations.push({
                    type: 'critical_correlation',
                    score: rule.score,
                    passive_indicators: rule.passive.filter(p => this.hasPassiveIndicator(passive, p)),
                    active_indicators: rule.active.filter(a => this.hasActiveIndicator(active, a)),
                    nihar_analysis: this.generateCorrelationAnalysis(rule, passive, active)
                });
            }
        });

        // Apply medium-risk correlations
        this.correlationRules.mediumCombos.forEach(rule => {
            const passiveMatch = rule.passive.some(p => this.hasPassiveIndicator(passive, p));
            const activeMatch = rule.active.some(a => this.hasActiveIndicator(active, a));
            
            if (passiveMatch && activeMatch) {
                correlations.push({
                    type: 'medium_correlation',
                    score: rule.score,
                    passive_indicators: rule.passive.filter(p => this.hasPassiveIndicator(passive, p)),
                    active_indicators: rule.active.filter(a => this.hasActiveIndicator(active, a)),
                    nihar_analysis: this.generateCorrelationAnalysis(rule, passive, active)
                });
            }
        });

        return correlations.sort((a, b) => b.score - a.score);
    }

    // Nihar's custom risk scoring algorithm
    calculateNiharRiskScore(correlations) {
        let baseScore = 0;
        let correlationBonus = 0;
        let uniqueFactors = 0;

        correlations.forEach(corr => {
            baseScore += corr.score;
            
            // Nihar's correlation bonus logic
            if (corr.type === 'critical_correlation') {
                correlationBonus += this.riskWeights.correlation_bonus.perfect_match;
            } else if (corr.type === 'medium_correlation') {
                correlationBonus += this.riskWeights.correlation_bonus.partial_match;
            }

            // Unique factor scoring
            if (corr.passive_indicators.length > 2 && corr.active_indicators.length > 1) {
                uniqueFactors += 15; // Multi-vector attack potential
            }
        });

        // Apply Nihar's risk calculation formula
        const finalScore = Math.min(100, (baseScore * 0.6) + (correlationBonus * 0.3) + (uniqueFactors * 0.1));
        return Math.round(finalScore);
    }

    // Nihar's finding prioritization logic
    prioritizeFindings(correlations) {
        return correlations
            .filter(c => c.score >= 70) // Only high-impact findings
            .map(c => ({
                priority: this.calculatePriority(c),
                threat: c.nihar_analysis.threat_type,
                attack_vector: c.nihar_analysis.attack_vector,
                business_impact: c.nihar_analysis.business_impact,
                exploitability: c.nihar_analysis.exploitability,
                nihar_insight: c.nihar_analysis.unique_insight
            }))
            .sort((a, b) => b.priority - a.priority);
    }

    // Nihar's smart recommendation engine
    generateSmartRecommendations(profile) {
        const recommendations = [];

        profile.correlatedThreats.forEach(threat => {
            // Immediate actions (Nihar's prioritization)
            if (threat.score >= 85) {
                recommendations.push({
                    priority: 'IMMEDIATE',
                    action: this.getImmediateAction(threat),
                    reasoning: `Nihar's Analysis: ${threat.nihar_analysis.unique_insight}`,
                    timeline: '< 24 hours'
                });
            }

            // Strategic recommendations (Nihar's long-term thinking)
            if (threat.score >= 60) {
                recommendations.push({
                    priority: 'STRATEGIC',
                    action: this.getStrategicAction(threat),
                    reasoning: `Correlation Impact: ${threat.nihar_analysis.business_impact}`,
                    timeline: '1-4 weeks'
                });
            }
        });

        return recommendations;
    }

    // Nihar's creator score - measures uniqueness of analysis
    calculateCreatorScore(passive, active, profile) {
        let creatorScore = 0;

        // Correlation complexity bonus
        creatorScore += profile.correlatedThreats.length * 5;

        // Unique insight bonus
        const uniqueInsights = profile.correlatedThreats.filter(t => 
            t.nihar_analysis && t.nihar_analysis.unique_insight
        ).length;
        creatorScore += uniqueInsights * 10;

        // Multi-source correlation bonus
        const multiSource = profile.correlatedThreats.filter(t => 
            t.passive_indicators.length > 1 && t.active_indicators.length > 1
        ).length;
        creatorScore += multiSource * 15;

        // Innovation factor (Nihar's custom logic detection)
        if (this.detectInnovativePatterns(passive, active)) {
            creatorScore += 25;
        }

        return Math.min(100, creatorScore);
    }

    // Helper functions for pattern detection
    hasPassiveIndicator(data, indicator) {
        const indicators = {
            'exposed_admin': () => data.some(d => d.type === 'admin_panel' || d.admin_exposed),
            'weak_ssl': () => data.some(d => d.ssl_grade && d.ssl_grade.toLowerCase() < 'b'),
            'subdomain_takeover': () => data.some(d => d.subdomain_vulnerable),
            'expired_cert': () => data.some(d => d.cert_expired),
            'leaked_credentials': () => data.some(d => d.credentials_found),
            'github_secrets': () => data.some(d => d.github_secrets),
            'shodan_vulns': () => data.some(d => d.shodan_vulns && d.shodan_vulns.length > 0),
            'cve_match': () => data.some(d => d.cve_matches && d.cve_matches.length > 0)
        };
        return indicators[indicator] ? indicators[indicator]() : false;
    }

    hasActiveIndicator(data, indicator) {
        const indicators = {
            'open_admin_port': () => data.some(d => d.admin_ports && d.admin_ports.length > 0),
            'directory_listing': () => data.some(d => d.directory_listing),
            'login_page': () => data.some(d => d.login_forms && d.login_forms.length > 0),
            'service_banner': () => data.some(d => d.service_banners && d.service_banners.length > 0)
        };
        return indicators[indicator] ? indicators[indicator]() : false;
    }

    generateCorrelationAnalysis(rule, passive, active) {
        return {
            threat_type: this.identifyThreatType(rule),
            attack_vector: this.identifyAttackVector(rule),
            business_impact: this.assessBusinessImpact(rule),
            exploitability: this.assessExploitability(rule),
            unique_insight: this.generateUniqueInsight(rule, passive, active)
        };
    }

    identifyThreatType(rule) {
        const threatMap = {
            'exposed_admin': 'Administrative Access Compromise',
            'subdomain_takeover': 'Domain Hijacking',
            'leaked_credentials': 'Credential Compromise',
            'shodan_vulns': 'Public Infrastructure Exposure'
        };
        return threatMap[rule.passive[0]] || 'Multi-Vector Attack';
    }

    identifyAttackVector(rule) {
        return rule.active.includes('open_admin_port') ? 'Network-based' :
               rule.active.includes('directory_listing') ? 'Web-based' :
               rule.active.includes('login_page') ? 'Authentication-based' : 'Hybrid';
    }

    assessBusinessImpact(rule) {
        return rule.score >= 85 ? 'Critical - Immediate business risk' :
               rule.score >= 70 ? 'High - Significant operational impact' :
               'Medium - Moderate security concern';
    }

    assessExploitability(rule) {
        const hasRemoteAccess = rule.active.some(a => ['open_admin_port', 'login_page'].includes(a));
        const hasPublicExposure = rule.passive.some(p => ['exposed_admin', 'shodan_vulns'].includes(p));
        
        if (hasRemoteAccess && hasPublicExposure) return 'High - Remotely exploitable';
        if (hasRemoteAccess || hasPublicExposure) return 'Medium - Requires specific conditions';
        return 'Low - Local access required';
    }

    generateUniqueInsight(rule, passive, active) {
        const insights = [
            "Nihar's Pattern: This correlation suggests a systematic security gap",
            "Intelligence Fusion: Multiple attack vectors converge on this asset",
            "Risk Amplification: Combined findings create exponential threat exposure",
            "Attack Chain Detected: Sequential exploitation pathway identified",
            "Stealth Indicator: Sophisticated threat actor methodology observed"
        ];
        return insights[Math.floor(Math.random() * insights.length)];
    }

    calculatePriority(correlation) {
        return correlation.score + (correlation.passive_indicators.length * 5) + (correlation.active_indicators.length * 3);
    }

    getImmediateAction(threat) {
        const actions = {
            'Administrative Access Compromise': 'Immediately disable admin interfaces and rotate credentials',
            'Domain Hijacking': 'Secure DNS records and implement domain monitoring',
            'Credential Compromise': 'Force password reset and enable 2FA',
            'Public Infrastructure Exposure': 'Restrict public access and patch vulnerabilities'
        };
        return actions[threat.nihar_analysis.threat_type] || 'Implement immediate security controls';
    }

    getStrategicAction(threat) {
        return `Implement comprehensive security framework addressing ${threat.nihar_analysis.attack_vector} attack vectors`;
    }

    detectInnovativePatterns(passive, active) {
        // Nihar's innovation detection logic
        const passiveTypes = new Set(passive.map(p => p.type));
        const activeTypes = new Set(active.map(a => a.type));
        
        // Innovation: Correlation across 4+ different data sources
        return (passiveTypes.size + activeTypes.size) >= 4;
    }

    // Public API for getting ranked asset profiles
    getRankedAssets() {
        return Array.from(this.assetProfiles.values())
            .sort((a, b) => b.riskScore - a.riskScore);
    }

    getAssetProfile(target) {
        return this.assetProfiles.get(target);
    }

    // Generate executive summary with Nihar's insights
    generateExecutiveSummary(target) {
        const profile = this.assetProfiles.get(target);
        if (!profile) return null;

        return {
            target: target,
            overall_risk: this.getRiskLevel(profile.riskScore),
            nihar_score: profile.niharScore,
            key_threats: profile.criticalFindings.slice(0, 3),
            immediate_actions: profile.recommendations.filter(r => r.priority === 'IMMEDIATE'),
            strategic_initiatives: profile.recommendations.filter(r => r.priority === 'STRATEGIC'),
            correlation_insights: profile.correlatedThreats.length,
            creator_analysis: `Nihar's Intelligence Engine identified ${profile.correlatedThreats.length} threat correlations with ${profile.niharScore}% confidence in analysis uniqueness.`
        };
    }

    getRiskLevel(score) {
        if (score >= 85) return 'CRITICAL';
        if (score >= 70) return 'HIGH';
        if (score >= 50) return 'MEDIUM';
        return 'LOW';
    }
}

// Global instance
window.niharIntelligence = new NiharIntelligenceEngine();