/*
  🛡️ PhishGuard AI — Production Interactive Logic & API Client
  Includes: Real Server API Sync, Toast System, Sample Loaders, Text Highlighter, History Filters, Export Helpers
*/

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialise character counters for textarea
    const msgInput = document.getElementById('msg-input');
    if (msgInput) {
        msgInput.addEventListener('input', (e) => {
            const count = e.target.value.length;
            const counterEl = document.getElementById('char-count');
            if (counterEl) counterEl.innerText = `${count} / 5000 chars`;
        });
    }

    // 2. Query param auto tab switching
    const params = new URLSearchParams(window.location.search);
    const initialTab = params.get('tab');
    if (initialTab) {
        switchTab(initialTab);
    }

    // 3. Load logs if history view exists
    if (document.getElementById('history-table-body')) {
        loadHistoryLogs();
    }
});

// Mobile menu toggle
function toggleMobileMenu() {
    const navLinks = document.getElementById('nav-links-menu');
    if (navLinks) {
        navLinks.classList.toggle('open');
    }
}

// Toast notification helper
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const iconName = type === 'success' ? 'fa-circle-check' : (type === 'error' ? 'fa-circle-exclamation' : 'fa-circle-info');
    toast.innerHTML = `<i class="fa-solid ${iconName}"></i> <span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// Tab Switching logic on /analyze
function switchTab(type) {
    const urlBtn = document.getElementById('tab-url-btn');
    const msgBtn = document.getElementById('tab-msg-btn');
    const urlPanel = document.getElementById('url-scan-panel');
    const msgPanel = document.getElementById('msg-scan-panel');

    if (!urlBtn || !msgBtn) return;

    resetResultUI();

    if (type === 'url') {
        urlBtn.classList.add('active');
        msgBtn.classList.remove('active');
        urlPanel.style.display = 'block';
        msgPanel.style.display = 'none';
    } else {
        urlBtn.classList.remove('active');
        msgBtn.classList.add('active');
        urlPanel.style.display = 'none';
        msgPanel.style.display = 'block';
    }
}

function resetResultUI() {
    const placeholder = document.getElementById('result-placeholder');
    const loading = document.getElementById('result-loading');
    const active = document.getElementById('result-active');
    
    if (placeholder) placeholder.style.display = 'block';
    if (loading) loading.style.display = 'none';
    if (active) active.style.display = 'none';
}

/* 
  =========================================
  PRESET QUICK SAMPLES LOADERS
  =========================================
*/

const PRESET_SAMPLES = {
    urlPhishing: 'http://secure-login-paypal.com-verify.net/signin?token=92841',
    urlSuspicious: 'http://192.168.1.105/banking/update-account-recovery',
    urlLegitimate: 'https://google.com',
    
    msgScamBank: 'URGENT: Your mobile bank account has been suspended! Tap here to verify identity within 24 hours: http://bank-verify.info',
    msgScamCrypto: 'Congratulations! You were selected to receive 0.5 BTC reward. Claim your prize immediately: http://bit-claim.org/reward',
    msgSafe: 'Hi Sarah, your package delivery is scheduled for tomorrow between 2 PM and 4 PM. Track status at your delivery app.'
};

function loadSampleUrl(sampleKey) {
    switchTab('url');
    const input = document.getElementById('url-input');
    if (input && PRESET_SAMPLES[sampleKey]) {
        input.value = PRESET_SAMPLES[sampleKey];
        showToast('Sample URL loaded into scanner', 'info');
        document.getElementById('url-scan-form').dispatchEvent(new Event('submit'));
    }
}

function loadSampleMsg(sampleKey) {
    switchTab('message');
    const input = document.getElementById('msg-input');
    if (input && PRESET_SAMPLES[sampleKey]) {
        input.value = PRESET_SAMPLES[sampleKey];
        const counterEl = document.getElementById('char-count');
        if (counterEl) counterEl.innerText = `${input.value.length} / 5000 chars`;
        showToast('Sample Message loaded into scanner', 'info');
        document.getElementById('msg-scan-form').dispatchEvent(new Event('submit'));
    }
}

/* 
  =========================================
  REAL API SERVER CALLS & FALLBACK ENGINE
  =========================================
*/

let currentActiveResult = null;

async function handleUrlScanSubmit(e) {
    e.preventDefault();
    const urlInput = document.getElementById('url-input').value.trim();
    if (!urlInput) return;

    showLoadingState();

    try {
        const response = await fetch('/api/analyze-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.message || 'Server error');
        }

        const data = await response.json();
        const result = {
            type: 'url',
            content: data.content,
            score: data.risk_score,
            classification: data.classification,
            riskLevel: data.risk_level,
            explanation: data.explanation
        };

        currentActiveResult = result;
        renderScanResults(result);
        saveScanToLocalStorage(result);
        showToast('AI URL Phishing Analysis Complete', 'success');

    } catch (err) {
        console.warn('API fetch error, using local fallback:', err);
        const result = analyzeUrlLocally(urlInput);
        currentActiveResult = result;
        renderScanResults(result);
        saveScanToLocalStorage(result);
        showToast('URL Scan Complete (Offline Engine)', 'info');
    }
}

async function handleMsgScanSubmit(e) {
    e.preventDefault();
    const msgInput = document.getElementById('msg-input').value.trim();
    if (!msgInput) return;

    showLoadingState();

    try {
        const response = await fetch('/api/analyze-message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msgInput })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.message || 'Server error');
        }

        const data = await response.json();
        const result = {
            type: 'message',
            content: data.content,
            score: data.risk_score,
            classification: data.classification,
            riskLevel: data.risk_level,
            matchedPhrases: data.matched_patterns,
            explanation: data.explanation
        };

        currentActiveResult = result;
        renderScanResults(result);
        saveScanToLocalStorage(result);
        showToast('AI Scam Message Analysis Complete', 'success');

    } catch (err) {
        console.warn('API fetch error, using local fallback:', err);
        const result = analyzeMessageLocally(msgInput);
        currentActiveResult = result;
        renderScanResults(result);
        saveScanToLocalStorage(result);
        showToast('Message Scan Complete (Offline Engine)', 'info');
    }
}

function showLoadingState() {
    document.getElementById('result-placeholder').style.display = 'none';
    document.getElementById('result-loading').style.display = 'block';
    document.getElementById('result-active').style.display = 'none';
}

function renderScanResults(result) {
    document.getElementById('result-placeholder').style.display = 'none';
    document.getElementById('result-loading').style.display = 'none';
    document.getElementById('result-active').style.display = 'block';

    const scoreVal = Math.round(result.score);
    document.getElementById('risk-score-value').innerText = `${scoreVal}%`;
    
    // Gauge Animation
    const gaugeCircle = document.getElementById('gauge-stroke');
    if (gaugeCircle) {
        const offset = 471 - (scoreVal / 100) * 471;
        gaugeCircle.style.strokeDashoffset = offset;
    }

    // Set Risk Badge & Gauge Colors
    const badge = document.getElementById('result-risk-badge');
    badge.className = 'risk-badge';

    if (result.classification === 'Phishing' || result.classification === 'Scam') {
        if (gaugeCircle) gaugeCircle.style.stroke = 'var(--risk-high)';
        badge.classList.add('high');
        badge.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <span>${result.classification} Threat</span>`;
    } else if (result.classification === 'Suspicious') {
        if (gaugeCircle) gaugeCircle.style.stroke = 'var(--risk-medium)';
        badge.classList.add('medium');
        badge.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> <span>Suspicious</span>`;
    } else {
        if (gaugeCircle) gaugeCircle.style.stroke = 'var(--risk-low)';
        badge.classList.add('low');
        badge.innerHTML = `<i class="fa-solid fa-shield-check"></i> <span>Verified Safe</span>`;
    }

    // Highlighted Text Container for Messages
    const highlightedContainer = document.getElementById('highlighted-msg-container');
    if (highlightedContainer) {
        if (result.type === 'message' && result.matchedPhrases && result.matchedPhrases.length > 0) {
            highlightedContainer.style.display = 'block';
            let highlightedText = result.content;
            result.matchedPhrases.forEach(phrase => {
                const regex = new RegExp(`(${phrase})`, 'gi');
                highlightedText = highlightedText.replace(regex, `<span class="scam-tag">$1</span>`);
            });
            highlightedContainer.innerHTML = `
                <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.35rem; font-weight: 600;">
                    <i class="fa-solid fa-highlighter" style="color: var(--risk-high);"></i> Detected Threat Phrases:
                </div>
                ${highlightedText}
            `;
        } else {
            highlightedContainer.style.display = 'none';
        }
    }

    // Render Explanations
    const container = document.getElementById('factor-list-container');
    container.innerHTML = '';

    result.explanation.forEach(item => {
        const factorDiv = document.createElement('div');
        factorDiv.className = `factor-item ${item.type === 'warning' ? 'warning' : ''}`;
        
        const iconColor = item.type === 'warning' ? 'red' : 'green';
        const iconName = item.type === 'warning' ? 'fa-triangle-exclamation' : 'fa-circle-check';
        
        factorDiv.innerHTML = `
            <i class="fa-solid ${iconName} factor-icon ${iconColor}"></i>
            <span style="font-size: 0.85rem; color: var(--text-secondary);">${item.text}</span>
        `;
        container.appendChild(factorDiv);
    });
}

// Copy report to clipboard
function copyReportToClipboard() {
    if (!currentActiveResult) return;
    
    const r = currentActiveResult;
    const reportText = `🛡️ PhishGuard Security Audit Report
--------------------------------------
Content Scanned: ${r.content}
Scan Type: ${r.type.toUpperCase()}
Risk Score: ${Math.round(r.score)}%
Classification: ${r.classification}
Audit Timestamp: ${new Date().toLocaleString()}

Explainable AI Indicators:
${r.explanation.map(e => `- [${e.type.toUpperCase()}] ${e.text}`).join('\n')}
--------------------------------------
Verified by PhishGuard AI Threat Intelligence Server`;

    navigator.clipboard.writeText(reportText).then(() => {
        showToast('Threat Audit Report copied to clipboard!', 'success');
    }).catch(() => {
        showToast('Unable to copy report.', 'error');
    });
}

/* 
  =========================================
  LOCALSTORAGE & SERVER HISTORY SYNCHRONISATION
  =========================================
*/

function saveScanToLocalStorage(result) {
    let scans = JSON.parse(localStorage.getItem('phishguard_scans')) || [];
    
    const newScan = {
        id: 'scan_' + Date.now(),
        timestamp: new Date().toISOString(),
        type: result.type,
        content: result.content,
        score: result.score,
        classification: result.classification
    };
    
    scans.unshift(newScan);
    localStorage.setItem('phishguard_scans', JSON.stringify(scans));
}

async function loadHistoryLogs() {
    const tableBody = document.getElementById('history-table-body');
    const emptyState = document.getElementById('history-empty');
    if (!tableBody) return;

    const filterType = document.getElementById('filter-type') ? document.getElementById('filter-type').value : 'all';
    const filterRisk = document.getElementById('filter-risk') ? document.getElementById('filter-risk').value : 'all';
    const filterSort = document.getElementById('filter-sort') ? document.getElementById('filter-sort').value : 'date_desc';
    const searchQuery = document.getElementById('history-search') ? document.getElementById('history-search').value.toLowerCase().trim() : '';

    let scans = [];

    try {
        const response = await fetch(`/api/scan-history?type=${filterType}&risk_level=${filterRisk}&sort_by=${filterSort}`);
        if (response.ok) {
            const data = await response.json();
            scans = data.scans || [];
            if (data.stats) {
                updateStatsCountersWithData(data.stats);
            }
        } else {
            throw new Error('Not authenticated or server offline');
        }
    } catch (err) {
        // Fallback to localStorage if unauthenticated or offline
        scans = JSON.parse(localStorage.getItem('phishguard_scans')) || [];

        if (searchQuery) {
            scans = scans.filter(s => s.content.toLowerCase().includes(searchQuery));
        }

        if (filterType !== 'all') {
            scans = scans.filter(s => s.type === filterType);
        }

        if (filterRisk !== 'all') {
            scans = scans.filter(s => {
                const score = s.score;
                if (filterRisk === 'low') return score <= 30;
                if (filterRisk === 'medium') return score > 30 && score <= 70;
                if (filterRisk === 'high') return score > 70;
                return true;
            });
        }

        if (filterSort === 'date_desc') {
            scans.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        } else if (filterSort === 'date_asc') {
            scans.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        } else if (filterSort === 'risk_desc') {
            scans.sort((a, b) => b.score - a.score);
        }
        updateStatsCounters();
    }

    if (searchQuery && scans.length > 0) {
        scans = scans.filter(s => s.content.toLowerCase().includes(searchQuery));
    }

    tableBody.innerHTML = '';

    if (scans.length === 0) {
        emptyState.style.display = 'block';
        return;
    } else {
        emptyState.style.display = 'none';
    }

    scans.forEach(scan => {
        const tr = document.createElement('tr');
        
        const date = new Date(scan.timestamp);
        const dateStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

        const typeIcon = scan.type === 'url' 
            ? `<i class="fa-solid fa-link" style="color: var(--color-primary);" title="URL scan"></i>` 
            : `<i class="fa-solid fa-envelope-open-text" style="color: var(--risk-high);" title="Message scan"></i>`;

        let preview = scan.content;
        if (preview.length > 55) {
            preview = preview.substring(0, 52) + '...';
        }

        let riskClass = 'low';
        if (scan.score > 70) riskClass = 'high';
        else if (scan.score > 30) riskClass = 'medium';

        tr.innerHTML = `
            <td style="font-size: 0.85rem; color: var(--text-secondary);">${dateStr}</td>
            <td style="text-align: center; font-size: 1.1rem;">${typeIcon}</td>
            <td style="font-family: ${scan.type === 'url' ? 'var(--font-mono)' : 'inherit'}; font-size: 0.9rem; color: var(--text-primary); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${preview}</td>
            <td style="text-align: center; font-weight: 700; font-family: var(--font-display); color: var(--text-primary);">${Math.round(scan.score)}%</td>
            <td style="text-align: center;">
                <span class="risk-badge ${riskClass}">
                    ${scan.classification}
                </span>
            </td>
            <td style="text-align: center;">
                <button onclick="deleteScanItem('${scan.id}')" style="background: transparent; border: none; color: var(--text-muted); cursor: pointer; padding: 0.4rem;" title="Delete Record">
                    <i class="fa-regular fa-trash-can"></i>
                </button>
            </td>
        `;
        tableBody.appendChild(tr);
    });
}

function updateStatsCountersWithData(stats) {
    const totalEl = document.getElementById('stat-total');
    const highEl = document.getElementById('stat-high');
    const safeEl = document.getElementById('stat-safe');

    if (totalEl) totalEl.innerText = stats.total_scans;
    if (highEl) highEl.innerText = stats.high_risk_count;
    if (safeEl) safeEl.innerText = stats.safe_count;
}

function updateStatsCounters() {
    const scans = JSON.parse(localStorage.getItem('phishguard_scans')) || [];
    
    const total = scans.length;
    const high = scans.filter(s => s.score > 70).length;
    const safe = scans.filter(s => s.score <= 30).length;

    updateStatsCountersWithData({ total_scans: total, high_risk_count: high, safe_count: safe });
}

function applyFilters() {
    loadHistoryLogs();
}

async function deleteScanItem(id) {
    try {
        const response = await fetch(`/api/scans/${id}`, { method: 'DELETE' });
        if (response.ok) {
            showToast('Record deleted from database.', 'info');
        }
    } catch (e) {
        console.log('Server delete fallback to local delete');
    }

    let scans = JSON.parse(localStorage.getItem('phishguard_scans')) || [];
    scans = scans.filter(s => s.id !== id);
    localStorage.setItem('phishguard_scans', JSON.stringify(scans));
    loadHistoryLogs();
}

function clearAllHistory() {
    if (confirm('Are you sure you want to clear your scan history?')) {
        localStorage.removeItem('phishguard_scans');
        loadHistoryLogs();
        showToast('Scan history cleared.', 'info');
    }
}

function exportHistoryData() {
    const scans = JSON.parse(localStorage.getItem('phishguard_scans')) || [];
    if (scans.length === 0) {
        showToast('No scan history available to export.', 'error');
        return;
    }

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scans, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishguard_logs_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast('Exported scan history logs as JSON!', 'success');
}

/* 
  =========================================
  OFFLINE HEURISTIC ENGINE (FALLBACK)
  =========================================
*/

function analyzeUrlLocally(url) {
    let score = 10;
    const indicators = [];

    if (url.startsWith('http://')) {
        score += 25;
        indicators.push({ type: 'warning', text: 'Uses insecure HTTP protocol instead of encrypted HTTPS.' });
    } else if (url.startsWith('https://')) {
        indicators.push({ type: 'safe', text: 'Uses SSL encryption protocol (HTTPS).' });
    }

    if (url.length > 70) {
        score += 15;
        indicators.push({ type: 'warning', text: `Unusually long URL string (${url.length} chars) often used to conceal real domains.` });
    }

    const ipPattern = /^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}/;
    if (ipPattern.test(url)) {
        score += 35;
        indicators.push({ type: 'warning', text: 'Domain resolves to a raw IP address, bypassing official DNS validation.' });
    }

    const hostname = url.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    const dots = (hostname.match(/\./g) || []).length;
    if (dots >= 3) {
        score += 20;
        indicators.push({ type: 'warning', text: `Multiple subdomains detected (${dots}), indicating spoofed domain layering.` });
    }

    const keywords = ['paypal', 'bank', 'secure', 'login', 'verify', 'update', 'signin', 'account', 'recovery', 'netflix', 'amazon', 'apple'];
    const matched = keywords.filter(kw => url.toLowerCase().includes(kw));
    if (matched.length > 0) {
        score += (matched.length * 20);
        indicators.push({ type: 'warning', text: `Contains high-risk brand keywords: "${matched.join(', ')}"` });
    }

    score = Math.min(score, 100);

    let classification = 'Legitimate';
    let riskLevel = 'Low';
    if (score > 70) {
        classification = 'Phishing';
        riskLevel = 'High';
    } else if (score > 30) {
        classification = 'Suspicious';
        riskLevel = 'Medium';
    }

    if (indicators.filter(i => i.type === 'warning').length === 0) {
        indicators.push({ type: 'safe', text: 'Domain SSL certificate appears valid.' });
        indicators.push({ type: 'safe', text: 'No brand name spoofing signatures found.' });
    }

    return {
        type: 'url',
        content: url,
        score: score,
        classification: classification,
        riskLevel: riskLevel,
        explanation: indicators
    };
}

function analyzeMessageLocally(message) {
    let score = 8;
    const indicators = [];
    const matchedPhrases = [];

    const urgencyWords = ['urgent', 'act now', 'limited time', 'immediate', 'verify within', '24 hours', 'suspended', 'blocked', 'closed'];
    const threatWords = ['court', 'jail', 'legal action', 'police', 'breach', 'security alert', 'unauthorized login'];
    const financialWords = ['free money', 'prize', 'gift card', 'cash reward', 'selected', 'winner', 'unclaimed', 'btc', 'investment', 'reward', '0.5 btc'];
    const credWords = ['password', 'otp', 'pin', 'ssn', 'social security', 'credit card', 'banking login', 'identity'];

    const mUrgent = urgencyWords.filter(w => message.toLowerCase().includes(w));
    if (mUrgent.length > 0) {
        score += 25;
        matchedPhrases.push(...mUrgent);
        indicators.push({ type: 'warning', text: `High urgency hook detected: "${mUrgent.slice(0, 3).join(', ')}"` });
    }

    const mThreat = threatWords.filter(w => message.toLowerCase().includes(w));
    if (mThreat.length > 0) {
        score += 30;
        matchedPhrases.push(...mThreat);
        indicators.push({ type: 'warning', text: `Coercive threat language detected: "${mThreat.slice(0, 2).join(', ')}"` });
    }

    const mFin = financialWords.filter(w => message.toLowerCase().includes(w));
    if (mFin.length > 0) {
        score += 25;
        matchedPhrases.push(...mFin);
        indicators.push({ type: 'warning', text: `Unrealistic financial bait hook: "${mFin.slice(0, 2).join(', ')}"` });
    }

    const mCred = credWords.filter(w => message.toLowerCase().includes(w));
    if (mCred.length > 0) {
        score += 35;
        matchedPhrases.push(...mCred);
        indicators.push({ type: 'warning', text: `Sensitive information / credential request: "${mCred.slice(0, 2).join(', ')}"` });
    }

    if (/https?:\/\/[^\s]+/.test(message)) {
        score += 15;
        indicators.push({ type: 'warning', text: 'Prompts user to click embedded link inside SMS/Message.' });
    }

    score = Math.min(score, 100);

    let classification = 'Safe';
    if (score > 70) classification = 'Scam';
    else if (score > 30) classification = 'Suspicious';

    if (indicators.length === 0) {
        indicators.push({ type: 'safe', text: 'No pressure tactics or urgency phrases found.' });
        indicators.push({ type: 'safe', text: 'No monetary or identity hooks detected.' });
    }

    return {
        type: 'message',
        content: message,
        score: score,
        classification: classification,
        matchedPhrases: matchedPhrases,
        explanation: indicators
    };
}

/* 
  =========================================
  UI UTILITIES & ACCORDIONS
  =========================================
*/

function toggleAccordion(header) {
    const item = header.parentElement;
    item.classList.toggle('active');
}

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;

    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = `<i class="fa-solid fa-eye-slash"></i>`;
    } else {
        input.type = 'password';
        btn.innerHTML = `<i class="fa-solid fa-eye"></i>`;
    }
}

function checkPasswordStrength() {
    const password = document.getElementById('reg-password').value;
    const strengthBar = document.getElementById('password-strength-bar');
    const strengthText = document.getElementById('password-strength-text');

    if (!strengthBar || !strengthText) return;

    if (password.length === 0) {
        strengthBar.style.width = '0%';
        strengthText.innerText = 'Min. 8 characters with letters and numbers';
        strengthText.style.color = 'var(--text-muted)';
        return;
    }

    let score = 0;
    if (password.length >= 8) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score === 1) {
        strengthBar.style.width = '25%';
        strengthBar.style.backgroundColor = 'var(--risk-high)';
        strengthText.innerText = 'Weak password';
        strengthText.style.color = 'var(--risk-high)';
    } else if (score === 2) {
        strengthBar.style.width = '50%';
        strengthBar.style.backgroundColor = 'var(--risk-medium)';
        strengthText.innerText = 'Medium strength';
        strengthText.style.color = 'var(--risk-medium)';
    } else if (score === 3) {
        strengthBar.style.width = '75%';
        strengthBar.style.backgroundColor = 'var(--color-primary)';
        strengthText.innerText = 'Strong password';
        strengthText.style.color = 'var(--text-secondary)';
    } else if (score === 4) {
        strengthBar.style.width = '100%';
        strengthBar.style.backgroundColor = 'var(--risk-low)';
        strengthText.innerText = 'Very strong password';
        strengthText.style.color = 'var(--risk-low)';
    }
}

function validateRegisterForm(e) {
    const password = document.getElementById('reg-password').value;
    const confirmPass = document.getElementById('reg-password-confirm').value;

    if (password !== confirmPass) {
        showToast('Passwords do not match!', 'error');
        e.preventDefault();
        return false;
    }
    
    if (password.length < 8) {
        showToast('Password must be at least 8 characters long!', 'error');
        e.preventDefault();
        return false;
    }

    return true;
}
