const socket = io();
const stats = { "Benign": 0, "Probe": 0, "DoS": 0, "R2L": 0, "U2R": 0 };
let total = 0, threats = 0, isPaused = false;
let threatCounter = 0; // Tracks threats per interval for the line chart

// --- 1. AUDIO ALERT SYSTEM ---
// Standard Web Audio API to bypass file dependency
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();

function playAlertSound(type) {
    // Only sound for high-risk categories
    if (type === "Benign" || type === "Probe") return;

    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    oscillator.type = 'square'; 
    oscillator.frequency.setValueAtTime(880, audioCtx.currentTime); 
    oscillator.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.2); 

    gainNode.gain.setValueAtTime(0.05, audioCtx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);

    oscillator.start();
    oscillator.stop(audioCtx.currentTime + 0.3);
}

// --- 2. CHART CONFIGURATION ---

// Distribution Chart (Polar Area)
const threatCtx = document.getElementById('threatChart').getContext('2d');
const threatChart = new Chart(threatCtx, {
    type: 'polarArea',
    data: {
        labels: Object.keys(stats),
        datasets: [{
            data: Object.values(stats),
            backgroundColor: [
                'rgba(0, 255, 136, 0.5)', // Benign
                'rgba(255, 235, 59, 0.5)', // Probe
                'rgba(255, 152, 0, 0.5)', // DoS
                'rgba(244, 67, 54, 0.5)', // R2L
                'rgba(156, 39, 176, 0.5)'  // U2R
            ],
            borderColor: 'rgba(255, 255, 255, 0.1)'
        }]
    },
    options: { 
        plugins: { legend: { display: false } }, 
        scales: { r: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { display: false } } } 
    }
});

// Intensity Chart (Line - Fixed "Not Showing" logic)
const intensityCtx = document.getElementById('intensityChart').getContext('2d');
const intensityChart = new Chart(intensityCtx, {
    type: 'line',
    data: {
        labels: Array(20).fill(''), // X-axis history length
        datasets: [{
            label: 'Threat Spikes',
            data: Array(20).fill(0),
            borderColor: '#ff003c',
            backgroundColor: 'rgba(255, 0, 60, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
            x: { display: false }
        }
    }
});

// --- 3. LIVE DATA LOGIC ---

// Interval to push data to the Intensity Chart every 2 seconds
setInterval(() => {
    intensityChart.data.datasets[0].data.push(threatCounter);
    intensityChart.data.datasets[0].data.shift();
    threatCounter = 0; // Reset for next 2-second window
    intensityChart.update('none'); // Update without heavy animation
}, 2000);

socket.on('new_pkt', (data) => {
    total++;
    document.getElementById('total-pkts').innerText = total;

    // Logic for Alerts
    if (data.alert) {
        threats++;
        threatCounter++; // Feed the intensity graph
        document.getElementById('threat-pkts').innerText = threats;
        playAlertSound(data.label);
    }

    // UI Table Update
    if (!isPaused) {
        const tbody = document.getElementById('log-body');
        const row = tbody.insertRow(0);
        if (data.alert) row.className = "threat-critical";
        
        row.innerHTML = `
            <td class="text-info small">${data.time}</td>
            <td class="fw-bold">${data.src}</td>
            <td><span class="badge ${data.alert ? 'bg-danger' : 'bg-success'}">${data.label}</span></td>
            <td class="text-secondary">${data.alert ? 'HIGH' : 'LOW'}</td>
        `;
        if (tbody.rows.length > 25) tbody.deleteRow(25);
    }

    // Update Distribution Chart
    stats[data.label]++;
    threatChart.data.datasets[0].data = Object.values(stats);
    threatChart.update('none');
});

// --- 4. UI CONTROLS ---

document.getElementById('pause-btn').onclick = function() {
    isPaused = !isPaused;
    this.innerText = isPaused ? "RESUME FEED" : "FREEZE FEED";
    this.classList.toggle('btn-outline-info');
    this.classList.toggle('btn-info');
};

function clearLogs() {
    document.getElementById('log-body').innerHTML = '';
}

// ... (All your existing chart and socket code) ...

// --- 5. REPORT GENERATION (CSV Export) ---
function downloadReport() {
    const rows = document.querySelectorAll("#log-body tr");
    if (rows.length === 0) {
        alert("No data available to export. Please wait for packets to be captured.");
        return;
    }

    // Initialize CSV content with headers
    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "Timestamp,Source IP,Classification,Risk Level\n";

    // Loop through table rows and extract data
    rows.forEach(row => {
        const cols = row.querySelectorAll("td");
        if (cols.length >= 4) {
            const time = cols[0].innerText;
            const src = cols[1].innerText;
            const label = cols[2].innerText;
            const risk = cols[3].innerText;
            
            // Clean data (remove commas to avoid breaking CSV format)
            const cleanRow = [time, src, label, risk].map(v => `"${v.replace(/"/g, '""')}"`);
            csvContent += cleanRow.join(",") + "\n";
        }
    });

    // Create a hidden link and trigger the download
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `NIDS_Threat_Report_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    
    link.click(); // Trigger download
    document.body.removeChild(link); // Clean up
}

function clearLogs() { 
    if(confirm("Are you sure you want to clear all current logs?")) {
        document.getElementById('log-body').innerHTML = ''; 
    }
}