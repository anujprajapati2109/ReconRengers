class IntelligentPopupSystem {
    constructor() {
        this.userBehavior = {
            toolsUsed: [],
            lastTool: '',
            scanCount: 0,
            startTime: Date.now()
        };
        this.init();
    }

    init() {
        this.trackActivity();
    }

    trackActivity() {
        document.addEventListener('click', (e) => {
            if (e.target.closest('.tool-btn')) {
                const tool = e.target.textContent.trim();
                this.userBehavior.toolsUsed.push(tool);
                this.userBehavior.lastTool = tool;
                this.predictAndReact();
            }
        });
    }

    predictAndReact() {
        const { toolsUsed, lastTool } = this.userBehavior;
        const timeSpent = Math.floor((Date.now() - this.userBehavior.startTime) / 60000);
        
        let message = '';
        
        // Predict based on tool pattern
        if (lastTool.includes('WHOIS')) {
            message = "🕵️ Starting with basics? Smart move! Domain intel first.";
        } else if (lastTool.includes('Subdomain')) {
            message = "🎯 Hunting subdomains? You're thinking like a real hacker!";
        } else if (lastTool.includes('Port')) {
            message = "🚪 Knocking on doors? Let's see what's open...";
        } else if (lastTool.includes('Brute')) {
            message = "💥 Going aggressive? Make sure you're protected!";
        } else if (lastTool.includes('XSS')) {
            message = "⚡ XSS hunting mode! Time to break some websites.";
        } else if (lastTool.includes('DOS')) {
            message = "🔥 Full attack mode! Hope your VPN is on...";
        } else if (toolsUsed.length > 5) {
            message = "🧠 You're on fire! Judges will love this methodology.";
        } else {
            message = "🚀 Keep exploring! Every click reveals new secrets.";
        }
        
        this.showPopup(message);
    }

    showPopup(message) {
        const existing = document.querySelector('.intelligent-popup');
        if (existing) existing.remove();

        const popup = document.createElement('div');
        popup.className = 'intelligent-popup';
        popup.innerHTML = `
            <div class="popup-content">
                <span class="popup-close">&times;</span>
                <div class="popup-message">${message}</div>
            </div>
        `;

        document.body.appendChild(popup);
        setTimeout(() => popup.remove(), 3000);
        popup.querySelector('.popup-close').onclick = () => popup.remove();
    }

    triggerScanCompletePopup() {
        this.userBehavior.scanCount++;
        const messages = [
            "🏆 Scan complete! You're becoming a recon master!",
            "✨ Nice work! Your technique is getting sharper.",
            "🔥 Another successful scan! Hackathon judges impressed."
        ];
        this.showPopup(messages[Math.floor(Math.random() * messages.length)]);
    }
}

// Initialize popup system
const intelligentPopup = new IntelligentPopupSystem();