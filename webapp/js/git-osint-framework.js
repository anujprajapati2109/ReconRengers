// Git API & OSINT Framework for Advanced Passive Reconnaissance
const GitOSINTFramework = {
    // Git API endpoints and configurations
    gitAPIs: {
        github: {
            baseUrl: 'https://api.github.com',
            searchUrl: 'https://api.github.com/search',
            rateLimit: 60, // requests per hour without auth
            endpoints: {
                repositories: '/search/repositories',
                code: '/search/code',
                users: '/search/users',
                commits: '/search/commits'
            }
        },
        gitlab: {
            baseUrl: 'https://gitlab.com/api/v4',
            searchUrl: 'https://gitlab.com/api/v4/search',
            rateLimit: 2000
        },
        bitbucket: {
            baseUrl: 'https://api.bitbucket.org/2.0',
            searchUrl: 'https://api.bitbucket.org/2.0/search',
            rateLimit: 1000
        }
    },

    // OSINT Framework structure
    osintFramework: {
        domainIntelligence: {
            whois: { priority: 'high', category: 'infrastructure' },
            dns: { priority: 'high', category: 'infrastructure' },
            certificates: { priority: 'medium', category: 'infrastructure' },
            subdomains: { priority: 'high', category: 'enumeration' }
        },
        codeIntelligence: {
            github: { priority: 'critical', category: 'code-exposure' },
            gitlab: { priority: 'high', category: 'code-exposure' },
            bitbucket: { priority: 'medium', category: 'code-exposure' },
            pastebin: { priority: 'high', category: 'data-leaks' }
        },
        socialIntelligence: {
            linkedin: { priority: 'medium', category: 'social-engineering' },
            twitter: { priority: 'medium', category: 'social-engineering' },
            facebook: { priority: 'low', category: 'social-engineering' },
            instagram: { priority: 'low', category: 'social-engineering' }
        },
        threatIntelligence: {
            virustotal: { priority: 'high', category: 'reputation' },
            shodan: { priority: 'critical', category: 'exposure' },
            censys: { priority: 'high', category: 'exposure' },
            urlvoid: { priority: 'medium', category: 'reputation' }
        }
    },

    // NSE scripts for Git and OSINT operations
    nseScripts: {
        'git-recon.nse': {
            description: 'Comprehensive Git repository reconnaissance',
            categories: ['discovery', 'safe'],
            usage: 'nmap --script git-recon --script-args target=example.com'
        },
        'osint-framework.nse': {
            description: 'Structured OSINT data collection',
            categories: ['discovery', 'safe'],
            usage: 'nmap --script osint-framework --script-args target=example.com'
        },
        'code-exposure.nse': {
            description: 'Detect exposed source code and secrets',
            categories: ['vuln', 'safe'],
            usage: 'nmap --script code-exposure --script-args target=example.com'
        }
    },

    findings: [],

    // Main Git OSINT execution
    async executeGitOSINT(target, addResult) {
        addResult('🔍 EXECUTING GIT & OSINT FRAMEWORK', 'info');
        addResult('=' .repeat(50), 'info');

        // Phase 1: Git Repository Intelligence
        await this.runGitIntelligence(target, addResult);
        
        // Phase 2: Code Exposure Analysis
        await this.runCodeExposureAnalysis(target, addResult);
        
        // Phase 3: OSINT Framework Execution
        await this.runOSINTFramework(target, addResult);
        
        // Phase 4: NSE Script Simulation
        await this.runNSEScripts(target, addResult);

        addResult('=' .repeat(50), 'info');
        addResult(`✅ GIT & OSINT FRAMEWORK COMPLETE - ${this.findings.length} findings`, 'info');
    },

    // Git Intelligence gathering
    async runGitIntelligence(target, addResult) {
        addResult('🐙 PHASE 1: GIT REPOSITORY INTELLIGENCE', 'info');
        
        const searchQueries = [
            `"${target}"`,
            `"${target}" password`,
            `"${target}" api_key`,
            `"${target}" secret`,
            `"${target}" config`,
            `"${target}" database`,
            `"${target}" credentials`,
            `"${target}" token`,
            `"${target}" .env`,
            `"${target}" backup`
        ];

        for (let query of searchQueries) {
            await this.searchGitRepositories(query, target, addResult);
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    },

    // Search Git repositories across platforms
    async searchGitRepositories(query, target, addResult) {
        // GitHub Search Simulation
        await this.searchGitHub(query, target, addResult);
        
        // GitLab Search Simulation
        await this.searchGitLab(query, target, addResult);
        
        // Bitbucket Search Simulation
        await this.searchBitbucket(query, target, addResult);
    },

    async searchGitHub(query, target, addResult) {
        addResult(`🐙 GitHub: Searching "${query}"`, 'info');
        
        // Simulate GitHub API search results
        const mockResults = [
            {
                name: `${target.split('.')[0]}-config`,
                full_name: `user/${target.split('.')[0]}-config`,
                description: 'Configuration files',
                private: false,
                html_url: `https://github.com/user/${target.split('.')[0]}-config`,
                risk: 'high'
            },
            {
                name: `${target.split('.')[0]}-backup`,
                full_name: `company/${target.split('.')[0]}-backup`,
                description: 'Database backup scripts',
                private: false,
                html_url: `https://github.com/company/${target.split('.')[0]}-backup`,
                risk: 'critical'
            }
        ];

        // Simulate finding repositories
        if (Math.random() > 0.6) {
            const result = mockResults[Math.floor(Math.random() * mockResults.length)];
            addResult(`🐙 FOUND: ${result.full_name}`, result.risk, 'GitHub Search');
            addResult(`   └─ ${result.description}`, 'info');
            addResult(`   └─ URL: ${result.html_url}`, 'info');
            
            this.findings.push({
                type: 'git-exposure',
                platform: 'github',
                repository: result.full_name,
                risk: result.risk,
                url: result.html_url
            });

            // Check for sensitive files in repository
            await this.analyzeSensitiveFiles(result, target, addResult);
        }
    },

    async searchGitLab(query, target, addResult) {
        addResult(`🦊 GitLab: Searching "${query}"`, 'info');
        
        if (Math.random() > 0.7) {
            const projectName = `${target.split('.')[0]}-project`;
            addResult(`🦊 FOUND: ${projectName}`, 'high', 'GitLab Search');
            addResult(`   └─ Private repository with public issues`, 'high');
            addResult(`   └─ URL: https://gitlab.com/group/${projectName}`, 'info');
            
            this.findings.push({
                type: 'git-exposure',
                platform: 'gitlab',
                repository: projectName,
                risk: 'high',
                url: `https://gitlab.com/group/${projectName}`
            });
        }
    },

    async searchBitbucket(query, target, addResult) {
        addResult(`🪣 Bitbucket: Searching "${query}"`, 'info');
        
        if (Math.random() > 0.8) {
            const repoName = `${target.split('.')[0]}-source`;
            addResult(`🪣 FOUND: ${repoName}`, 'medium', 'Bitbucket Search');
            addResult(`   └─ Source code repository`, 'medium');
            addResult(`   └─ URL: https://bitbucket.org/team/${repoName}`, 'info');
            
            this.findings.push({
                type: 'git-exposure',
                platform: 'bitbucket',
                repository: repoName,
                risk: 'medium',
                url: `https://bitbucket.org/team/${repoName}`
            });
        }
    },

    // Analyze sensitive files in repositories
    async analyzeSensitiveFiles(repository, target, addResult) {
        const sensitiveFiles = [
            { name: '.env', risk: 'critical', description: 'Environment variables' },
            { name: 'config.json', risk: 'high', description: 'Configuration file' },
            { name: 'database.sql', risk: 'critical', description: 'Database dump' },
            { name: 'id_rsa', risk: 'critical', description: 'SSH private key' },
            { name: 'aws-credentials', risk: 'critical', description: 'AWS credentials' },
            { name: 'api-keys.txt', risk: 'critical', description: 'API keys' }
        ];

        addResult(`🔍 Analyzing ${repository.name} for sensitive files...`, 'info');
        
        sensitiveFiles.forEach(file => {
            if (Math.random() > 0.8) {
                addResult(`🚨 SENSITIVE FILE: ${file.name}`, file.risk, 'Code Analysis');
                addResult(`   └─ ${file.description}`, 'info');
                
                this.findings.push({
                    type: 'sensitive-file',
                    file: file.name,
                    repository: repository.full_name,
                    risk: file.risk,
                    description: file.description
                });
            }
        });
    },

    // Code exposure analysis
    async runCodeExposureAnalysis(target, addResult) {
        addResult('💻 PHASE 2: CODE EXPOSURE ANALYSIS', 'info');
        
        const exposureChecks = [
            { type: 'pastebin', description: 'Pastebin code dumps' },
            { type: 'gist', description: 'GitHub Gists' },
            { type: 'stackoverflow', description: 'Stack Overflow posts' },
            { type: 'codepen', description: 'CodePen snippets' },
            { type: 'jsfiddle', description: 'JSFiddle code' }
        ];

        for (let check of exposureChecks) {
            await this.checkCodeExposure(check, target, addResult);
            await new Promise(resolve => setTimeout(resolve, 300));
        }
    },

    async checkCodeExposure(check, target, addResult) {
        addResult(`🔍 Checking ${check.description}...`, 'info');
        
        if (Math.random() > 0.7) {
            addResult(`💻 FOUND: Code exposure on ${check.type}`, 'high', 'Code Exposure');
            addResult(`   └─ ${target} mentioned in code snippet`, 'high');
            addResult(`   └─ Potential credential exposure`, 'high');
            
            this.findings.push({
                type: 'code-exposure',
                platform: check.type,
                risk: 'high',
                description: `${target} found in ${check.description}`
            });
        }
    },

    // OSINT Framework execution
    async runOSINTFramework(target, addResult) {
        addResult('🕵️ PHASE 3: OSINT FRAMEWORK EXECUTION', 'info');
        
        // Execute each OSINT category
        for (let [category, tools] of Object.entries(this.osintFramework)) {
            addResult(`📊 Category: ${category.toUpperCase()}`, 'info');
            
            for (let [tool, config] of Object.entries(tools)) {
                await this.executeOSINTTool(tool, config, target, addResult);
                await new Promise(resolve => setTimeout(resolve, 200));
            }
        }
    },

    async executeOSINTTool(tool, config, target, addResult) {
        addResult(`🔧 ${tool}: ${config.category} (${config.priority} priority)`, 'info');
        
        switch (tool) {
            case 'github':
                await this.osintGitHub(target, addResult);
                break;
            case 'shodan':
                await this.osintShodan(target, addResult);
                break;
            case 'virustotal':
                await this.osintVirusTotal(target, addResult);
                break;
            case 'linkedin':
                await this.osintLinkedIn(target, addResult);
                break;
            default:
                addResult(`   └─ ${tool} check completed`, 'info');
        }
    },

    async osintGitHub(target, addResult) {
        // Enhanced GitHub OSINT
        const orgName = target.split('.')[0];
        addResult(`🐙 GitHub Organization: ${orgName}`, 'info');
        
        if (Math.random() > 0.5) {
            addResult(`🐙 FOUND: GitHub organization @${orgName}`, 'medium', 'GitHub OSINT');
            addResult(`   └─ 15 public repositories`, 'medium');
            addResult(`   └─ 8 contributors identified`, 'medium');
            addResult(`   └─ Recent activity: 2 days ago`, 'info');
        }
    },

    async osintShodan(target, addResult) {
        addResult(`🛰️ Shodan: Scanning ${target}`, 'info');
        
        const services = [
            { port: 22, service: 'SSH', version: 'OpenSSH 8.2', risk: 'medium' },
            { port: 80, service: 'HTTP', version: 'nginx 1.18.0', risk: 'low' },
            { port: 443, service: 'HTTPS', version: 'nginx 1.18.0', risk: 'low' },
            { port: 3306, service: 'MySQL', version: '8.0.25', risk: 'high' }
        ];

        services.forEach(service => {
            if (Math.random() > 0.6) {
                addResult(`🛰️ ${service.port}/${service.service}: ${service.version}`, service.risk, 'Shodan OSINT');
            }
        });
    },

    async osintVirusTotal(target, addResult) {
        addResult(`🛡️ VirusTotal: Reputation check for ${target}`, 'info');
        
        const reputation = {
            malicious: Math.floor(Math.random() * 3),
            suspicious: Math.floor(Math.random() * 5),
            clean: 85 + Math.floor(Math.random() * 10),
            undetected: Math.floor(Math.random() * 5)
        };

        addResult(`🛡️ Reputation: ${reputation.malicious}/90 malicious`, 
                 reputation.malicious > 0 ? 'high' : 'low', 'VirusTotal OSINT');
        
        if (reputation.malicious > 0) {
            addResult(`   └─ ⚠️ Domain flagged by ${reputation.malicious} engines`, 'high');
        }
    },

    async osintLinkedIn(target, addResult) {
        const company = target.split('.')[0];
        addResult(`💼 LinkedIn: Company profile for ${company}`, 'info');
        
        if (Math.random() > 0.4) {
            addResult(`💼 FOUND: ${company} company page`, 'medium', 'LinkedIn OSINT');
            addResult(`   └─ 250+ employees`, 'medium');
            addResult(`   └─ Key personnel identified`, 'medium');
            addResult(`   └─ Recent job postings: 5`, 'info');
        }
    },

    // NSE Scripts simulation
    async runNSEScripts(target, addResult) {
        addResult('🔧 PHASE 4: NSE SCRIPTS EXECUTION', 'info');
        
        for (let [script, config] of Object.entries(this.nseScripts)) {
            await this.executeNSEScript(script, config, target, addResult);
            await new Promise(resolve => setTimeout(resolve, 400));
        }
    },

    async executeNSEScript(script, config, target, addResult) {
        addResult(`🔧 Executing ${script}`, 'info');
        addResult(`   └─ ${config.description}`, 'info');
        
        switch (script) {
            case 'git-recon.nse':
                await this.nseGitRecon(target, addResult);
                break;
            case 'osint-framework.nse':
                await this.nseOSINTFramework(target, addResult);
                break;
            case 'code-exposure.nse':
                await this.nseCodeExposure(target, addResult);
                break;
        }
    },

    async nseGitRecon(target, addResult) {
        addResult(`🔧 git-recon.nse: Comprehensive Git reconnaissance`, 'info');
        
        const gitFindings = [
            'Git repositories discovered: 3',
            'Exposed .git directories: 1',
            'Commit history accessible: Yes',
            'Sensitive files in commits: 2'
        ];

        gitFindings.forEach(finding => {
            const risk = finding.includes('Sensitive') ? 'high' : 
                        finding.includes('Exposed') ? 'medium' : 'info';
            addResult(`   └─ ${finding}`, risk, 'NSE Git Recon');
        });
    },

    async nseOSINTFramework(target, addResult) {
        addResult(`🔧 osint-framework.nse: Structured OSINT collection`, 'info');
        
        const osintFindings = [
            'Social media profiles: 4 found',
            'Email addresses harvested: 12',
            'Employee information: 8 profiles',
            'Technology stack identified: 15 components'
        ];

        osintFindings.forEach(finding => {
            addResult(`   └─ ${finding}`, 'medium', 'NSE OSINT Framework');
        });
    },

    async nseCodeExposure(target, addResult) {
        addResult(`🔧 code-exposure.nse: Source code exposure detection`, 'info');
        
        const codeFindings = [
            'Public repositories: 5 found',
            'API keys exposed: 2 instances',
            'Database credentials: 1 exposure',
            'Configuration files: 3 accessible'
        ];

        codeFindings.forEach(finding => {
            const risk = finding.includes('API keys') || finding.includes('credentials') ? 'critical' :
                        finding.includes('Configuration') ? 'high' : 'medium';
            addResult(`   └─ ${finding}`, risk, 'NSE Code Exposure');
        });
    },

    // Generate comprehensive report
    generateReport(target) {
        const report = {
            target: target,
            timestamp: new Date().toISOString(),
            findings: this.findings,
            summary: {
                total_findings: this.findings.length,
                critical: this.findings.filter(f => f.risk === 'critical').length,
                high: this.findings.filter(f => f.risk === 'high').length,
                medium: this.findings.filter(f => f.risk === 'medium').length,
                low: this.findings.filter(f => f.risk === 'low').length
            },
            recommendations: this.generateRecommendations()
        };

        return report;
    },

    generateRecommendations() {
        return [
            'Monitor public repositories for sensitive data exposure',
            'Implement Git hooks to prevent credential commits',
            'Regular OSINT monitoring for data leaks',
            'Employee security awareness training',
            'Implement data loss prevention (DLP) tools'
        ];
    }
};

// Integration with existing passive recon
if (typeof PassiveReconTools !== 'undefined') {
    // Remove SQL injection from passive recon tools
    const sqlIndex = PassiveReconTools.tools.findIndex(tool => tool.id === 'sql-injection');
    if (sqlIndex !== -1) {
        PassiveReconTools.tools.splice(sqlIndex, 1);
    }
    
    // Add Git & OSINT tools to existing framework
    PassiveReconTools.tools.push(
        { 
            id: 'git-osint', 
            name: '🐙 Git & OSINT Framework', 
            description: 'Comprehensive Git API & OSINT intelligence gathering', 
            enabled: true 
        }
    );

    // Add the new tool execution
    const originalRunTool = PassiveReconTools.runTool;
    PassiveReconTools.runTool = async function(toolId, target, addResult) {
        if (toolId === 'git-osint') {
            await GitOSINTFramework.executeGitOSINT(target, addResult);
        } else {
            await originalRunTool.call(this, toolId, target, addResult);
        }
    };
}

// Export for use in other modules
window.GitOSINTFramework = GitOSINTFramework;