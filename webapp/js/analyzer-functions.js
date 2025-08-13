// Analyzer Functions - URL Threat Monitor & Pentest Training
function startThreatMonitoring() {
    const target = document.getElementById('threatTarget').value.trim();
    if (!target) {
        alert('Please enter a URL to monitor');
        return;
    }
    
    const results = document.getElementById('analysisResults');
    results.innerHTML = ''; // Clear previous results
    
    function addResult(msg, level = 'info') {
        const time = new Date().toLocaleTimeString();
        const levelIcon = level === 'critical' ? '🚨' : level === 'high' ? '⚠️' : level === 'medium' ? '📊' : '✅';
        results.innerHTML += `[${time}] ${levelIcon} ${msg}<br>`;
        results.scrollTop = results.scrollHeight;
    }
    
    // Execute URL threat monitoring
    URLThreatMonitor.executeURLWatch(target, addResult);
}

function startPentestTraining() {
    const results = document.getElementById('analysisResults');
    results.innerHTML = ''; // Clear previous results
    
    function addResult(msg, level = 'info') {
        const time = new Date().toLocaleTimeString();
        const levelIcon = level === 'critical' ? '🚨' : level === 'high' ? '⚠️' : level === 'medium' ? '📊' : '✅';
        results.innerHTML += `[${time}] ${levelIcon} ${msg}<br>`;
        results.scrollTop = results.scrollHeight;
    }
    
    // Execute pentest training integration
    PentestTraining.executePentestTraining('training-session', addResult);
}