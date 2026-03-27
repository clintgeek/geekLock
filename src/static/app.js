async function updateStats() {
    try {
        const response = await fetch('/stats');
        const data = await response.json();
        
        document.getElementById('encryptions').innerText = data.encryptions;
        document.getElementById('decryptions').innerText = data.decryptions;
        
        // Format uptime
        const uptime = data.uptime_secs;
        const h = Math.floor(uptime / 3600);
        const m = Math.floor((uptime % 3600) / 60);
        const s = uptime % 60;
        
        let uptimeStr = '';
        if (h > 0) uptimeStr += `${h}h `;
        if (m > 0 || h > 0) uptimeStr += `${m}m `;
        uptimeStr += `${s}s`;
        
        document.getElementById('uptime').innerText = uptimeStr;
        
    } catch (error) {
        console.error('Failed to fetch stats:', error);
        document.getElementById('status-badge').innerText = 'Offline';
        document.getElementById('status-badge').style.borderColor = 'rgba(255, 68, 68, 0.3)';
        document.getElementById('status-badge').style.color = '#ff4444';
        document.getElementById('status-badge').style.background = 'rgba(255, 68, 68, 0.05)';
    }
}

// Update every 2 seconds
setInterval(updateStats, 2000);
// Initial update
updateStats();
