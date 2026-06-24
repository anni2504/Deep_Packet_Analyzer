// Application State
let selectedFile = null;
let rules = [];
let lastAnalysisResult = null;

// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('pcap-file');
const fileInfoBox = document.getElementById('file-info-box');
const selectedFileName = document.getElementById('selected-file-name');
const selectedFileSize = document.getElementById('selected-file-size');
const btnRemoveFile = document.getElementById('btn-remove-file');

const ruleType = document.getElementById('rule-type');
const ruleValue = document.getElementById('rule-value');
const btnAddRule = document.getElementById('btn-add-rule');
const rulesList = document.getElementById('rules-list');

const btnAnalyze = document.getElementById('btn-analyze');
const loadingState = document.getElementById('loading-state');
const resultsPanel = document.getElementById('results-panel');

const kpiTotalPackets = document.getElementById('kpi-total-packets');
const kpiTotalBytes = document.getElementById('kpi-total-bytes');
const kpiForwarded = document.getElementById('kpi-forwarded');
const kpiDropped = document.getElementById('kpi-dropped');

const appBreakdownList = document.getElementById('app-breakdown-list');
const lbThreadsList = document.getElementById('lb-threads-list');
const fpThreadsList = document.getElementById('fp-threads-list');

const sniSearch = document.getElementById('sni-search');
const sniTableBody = document.getElementById('sni-table-body');
const btnDownload = document.getElementById('btn-download');

// --- File Upload Logic ---

// Drag and drop handlers
['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    }, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
    }, false);
});

dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (fileInput.files.length > 0) {
        handleFileSelect(fileInput.files[0]);
    }
});

function handleFileSelect(file) {
    // Basic validation
    if (!file.name.endsWith('.pcap')) {
        alert('Invalid file format. Please upload a .pcap file.');
        return;
    }
    if (file.size > 50 * 1024 * 1024) {
        alert('File size exceeds the 50MB limit.');
        return;
    }

    selectedFile = file;
    selectedFileName.textContent = file.name;
    selectedFileSize.textContent = formatBytes(file.size);
    
    dropZone.style.display = 'none';
    fileInfoBox.style.display = 'flex';
    btnAnalyze.disabled = false;
}

btnRemoveFile.addEventListener('click', () => {
    selectedFile = null;
    fileInput.value = '';
    dropZone.style.display = 'flex';
    fileInfoBox.style.display = 'none';
    btnAnalyze.disabled = true;
});

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// --- Rules Manager Logic ---

btnAddRule.addEventListener('click', () => {
    const type = ruleType.value;
    const value = ruleValue.value.trim();
    
    if (value === '') {
        alert('Please enter a rule value.');
        return;
    }

    // Check for duplicates
    const isDuplicate = rules.some(r => r.type === type && r.value.toLowerCase() === value.toLowerCase());
    if (isDuplicate) {
        alert('This rule already exists.');
        return;
    }

    rules.push({ type, value });
    ruleValue.value = '';
    renderRules();
});

// Render the rules list in the UI
function renderRules() {
    if (rules.length === 0) {
        rulesList.innerHTML = '<li class="no-rules">No blocking rules configured yet.</li>';
        return;
    }

    rulesList.innerHTML = '';
    rules.forEach((rule, index) => {
        const li = document.createElement('li');
        
        let typeLabel = '';
        if (rule.type === 'ip') typeLabel = `<span class="rule-badge ip">IP</span>`;
        else if (rule.type === 'app') typeLabel = `<span class="rule-badge app">App</span>`;
        else if (rule.type === 'domain') typeLabel = `<span class="rule-badge domain">Domain</span>`;

        li.innerHTML = `
            <div>
                ${typeLabel}
                <span>${escapeHtml(rule.value)}</span>
            </div>
            <button type="button" class="btn-delete-rule" data-index="${index}">
                <i class="fa-solid fa-trash-can"></i>
            </button>
        `;
        rulesList.appendChild(li);
    });

    // Attach delete listeners
    document.querySelectorAll('.btn-delete-rule').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = parseInt(e.currentTarget.getAttribute('data-index'));
            rules.splice(index, 1);
            renderRules();
        });
    });
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// --- API Execution ---

btnAnalyze.addEventListener('click', async () => {
    if (!selectedFile) return;

    // Show loading spinner
    loadingState.style.display = 'block';
    resultsPanel.style.display = 'none';
    btnAnalyze.disabled = true;

    const formData = new FormData();
    formData.append('pcap', selectedFile);
    formData.append('rules', JSON.stringify(rules));

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || 'Server error occurred during analysis.');
        }

        const data = await response.json();
        
        if (data.success) {
            lastAnalysisResult = data;
            renderAnalysisResults(data.report);
            
            // Setup download link
            if (data.downloadToken) {
                btnDownload.style.display = 'inline-flex';
                btnDownload.onclick = () => {
                    window.location.href = `/api/download?token=${data.downloadToken}`;
                };
            } else {
                btnDownload.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Analysis error:', error);
        alert(`Analysis failed: ${error.message}`);
    } finally {
        loadingState.style.display = 'none';
        btnAnalyze.disabled = false;
    }
});

// --- Results Rendering ---

function renderAnalysisResults(report) {
    // Populate KPIs
    kpiTotalPackets.textContent = report.totalPackets.toLocaleString();
    kpiTotalBytes.textContent = formatBytes(report.totalBytes);
    kpiForwarded.textContent = report.forwarded.toLocaleString();
    kpiDropped.textContent = report.dropped.toLocaleString();

    // Populate Application Breakdown List
    appBreakdownList.innerHTML = '';
    if (report.appBreakdown.length === 0) {
        appBreakdownList.innerHTML = '<p class="section-desc">No applications detected.</p>';
    } else {
        report.appBreakdown.forEach(appData => {
            const row = document.createElement('div');
            row.className = `app-row ${appData.blocked ? 'blocked' : ''}`;
            
            row.innerHTML = `
                <div class="app-meta">
                    <span class="app-name">
                        ${escapeHtml(appData.app)}
                        ${appData.blocked ? '<span class="blocked-badge">Blocked</span>' : ''}
                    </span>
                    <span class="app-count-pct">${appData.count} (${appData.percentage}%)</span>
                </div>
                <div class="app-bar-bg">
                    <div class="app-bar-fill" style="width: 0%"></div>
                </div>
            `;
            appBreakdownList.appendChild(row);

            // Animate bar fill
            setTimeout(() => {
                row.querySelector('.app-bar-fill').style.width = `${appData.percentage}%`;
            }, 100);
        });
    }

    // Populate Thread Performance
    lbThreadsList.innerHTML = '';
    if (report.threadStats.lbs.length === 0) {
        lbThreadsList.innerHTML = '<p class="section-desc">No load balancer metrics.</p>';
    } else {
        const maxLbPackets = Math.max(...report.threadStats.lbs.map(t => t.count), 1);
        report.threadStats.lbs.forEach(thread => {
            const pct = (thread.count / maxLbPackets) * 100;
            const row = document.createElement('div');
            row.className = 'thread-row';
            row.innerHTML = `
                <span class="thread-label">Thread LB${thread.id}</span>
                <div class="thread-bar-bg">
                    <div class="thread-bar-fill" style="width: 0%"></div>
                </div>
                <span class="thread-val">${thread.count}</span>
            `;
            lbThreadsList.appendChild(row);

            setTimeout(() => {
                row.querySelector('.thread-bar-fill').style.width = `${pct}%`;
            }, 100);
        });
    }

    fpThreadsList.innerHTML = '';
    if (report.threadStats.fps.length === 0) {
        fpThreadsList.innerHTML = '<p class="section-desc">No processing thread metrics.</p>';
    } else {
        const maxFpPackets = Math.max(...report.threadStats.fps.map(t => t.count), 1);
        report.threadStats.fps.forEach(thread => {
            const pct = (thread.count / maxFpPackets) * 100;
            const row = document.createElement('div');
            row.className = 'thread-row';
            row.innerHTML = `
                <span class="thread-label">Thread FP${thread.id}</span>
                <div class="thread-bar-bg">
                    <div class="thread-bar-fill" style="width: 0%"></div>
                </div>
                <span class="thread-val">${thread.count}</span>
            `;
            fpThreadsList.appendChild(row);

            setTimeout(() => {
                row.querySelector('.thread-bar-fill').style.width = `${pct}%`;
            }, 100);
        });
    }

    // Populate Domains & SNIs Table
    renderSnisTable(report.detectedSnis);

    // Show results
    resultsPanel.style.display = 'block';
}

function getAppClass(appName) {
    const socialMedia = ['Facebook', 'Instagram', 'Twitter/X', 'Telegram', 'TikTok', 'Zoom', 'Discord', 'YouTube'];
    if (socialMedia.includes(appName)) return 'social';
    if (appName === 'DNS') return 'dns';
    if (appName === 'HTTP') return 'http';
    if (appName === 'HTTPS') return 'https';
    return 'generic';
}

function renderSnisTable(snis) {
    sniTableBody.innerHTML = '';
    if (snis.length === 0) {
        sniTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No domains extracted.</td></tr>';
        return;
    }

    // Check if domain is blocked by any active rules
    const isDomainBlocked = (domain, app) => {
        return rules.some(rule => {
            if (rule.type === 'ip') return false; // Port/IP checks not resolved fully on UI list table
            if (rule.type === 'app') return rule.value.toLowerCase() === app.toLowerCase();
            if (rule.type === 'domain') return domain.toLowerCase().includes(rule.value.toLowerCase());
            return false;
        });
    };

    snis.forEach(sni => {
        const row = document.createElement('tr');
        const blocked = isDomainBlocked(sni.domain, sni.app);
        
        row.innerHTML = `
            <td style="font-weight: 500;">${escapeHtml(sni.domain)}</td>
            <td><span class="app-tag ${getAppClass(sni.app)}">${escapeHtml(sni.app)}</span></td>
            <td class="status-cell">
                <span class="badge ${blocked ? 'blocked' : 'passed'}">${blocked ? 'Blocked' : 'Passed'}</span>
            </td>
        `;
        sniTableBody.appendChild(row);
    });
}

// Search Filter Logic for Table
sniSearch.addEventListener('input', () => {
    if (!lastAnalysisResult) return;
    const query = sniSearch.value.toLowerCase();
    const filtered = lastAnalysisResult.report.detectedSnis.filter(sni => 
        sni.domain.toLowerCase().includes(query) || sni.app.toLowerCase().includes(query)
    );
    renderSnisTable(filtered);
});
