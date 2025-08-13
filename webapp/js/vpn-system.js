// VPN System Integration
let vpnConnected = false;
let vpnCountry = 'US';

const vpnServers = [
    { country: 'US', name: 'United States', ip: '192.168.1.100', ping: '25ms' },
    { country: 'UK', name: 'United Kingdom', ip: '192.168.1.101', ping: '45ms' },
    { country: 'DE', name: 'Germany', ip: '192.168.1.102', ping: '35ms' },
    { country: 'JP', name: 'Japan', ip: '192.168.1.103', ping: '85ms' },
    { country: 'CA', name: 'Canada', ip: '192.168.1.104', ping: '30ms' }
];

function toggleVPN() {
    if (vpnConnected) {
        disconnectVPN();
    } else {
        showVPNServerSelection();
    }
}

function showVPNServerSelection() {
    const content = `
        <div class="vpn-selection">
            <h4>🌐 Select VPN Server</h4>
            <div class="server-list">
                ${vpnServers.map(server => `
                    <div class="server-item" onclick="connectToVPN('${server.country}')">
                        <span class="server-flag">${getCountryFlag(server.country)}</span>
                        <span class="server-name">${server.name}</span>
                        <span class="server-ping">${server.ping}</span>
                    </div>
                `).join('')}
            </div>
            <p><small>⚠️ VPN connection will anonymize your attack traffic</small></p>
        </div>
    `;
    
    showAdvancedPopup('VPN Server Selection', content, 'info');
}

function connectToVPN(country) {
    closeAdvancedPopup(document.querySelector('.advanced-popup-overlay'));
    
    const server = vpnServers.find(s => s.country === country);
    const statusEl = document.getElementById('vpnStatus');
    const toggleEl = document.getElementById('vpnToggle');
    
    statusEl.innerHTML = '🟡 VPN: Connecting...';
    toggleEl.textContent = 'Connecting...';
    toggleEl.disabled = true;
    
    setTimeout(() => {
        vpnConnected = true;
        vpnCountry = country;
        statusEl.innerHTML = `🟢 VPN: Connected (${getCountryFlag(country)} ${server.name})`;
        statusEl.className = 'vpn-connected';
        toggleEl.textContent = 'Disconnect VPN';
        toggleEl.disabled = false;
        
        showAlert(`🟢 VPN Connected to ${server.name}`, 'success');
    }, 2000);
}

function disconnectVPN() {
    const statusEl = document.getElementById('vpnStatus');
    const toggleEl = document.getElementById('vpnToggle');
    
    statusEl.innerHTML = '🟡 VPN: Disconnecting...';
    toggleEl.textContent = 'Disconnecting...';
    toggleEl.disabled = true;
    
    setTimeout(() => {
        vpnConnected = false;
        statusEl.innerHTML = '🔴 VPN: Disconnected';
        statusEl.className = 'vpn-disconnected';
        toggleEl.textContent = 'Connect VPN';
        toggleEl.disabled = false;
        
        showAlert('🔴 VPN Disconnected', 'warning');
    }, 1500);
}

function getCountryFlag(country) {
    const flags = {
        'US': '🇺🇸',
        'UK': '🇬🇧', 
        'DE': '🇩🇪',
        'JP': '🇯🇵',
        'CA': '🇨🇦'
    };
    return flags[country] || '🌐';
}

function isVPNRequired() {
    return !vpnConnected;
}

// Integrate VPN check into attack functions
function checkVPNBeforeAttack(attackType) {
    if (!vpnConnected) {
        if (confirm(`⚠️ VPN NOT CONNECTED ⚠️\n\nRunning ${attackType} without VPN protection exposes your real IP address.\n\nConnect to VPN first for anonymity?\n\nClick OK to connect VPN or Cancel to proceed without protection.`)) {
            showVPNServerSelection();
            return false;
        }
    }
    return true;
}