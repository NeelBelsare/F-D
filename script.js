// ==========================================
// 1. RENDER API CONFIGURATION
// ==========================================
// Properly formatted URL including https:// and .onrender.com
const BACKEND_URL = 'https://dep-d9fhlujrjlhs73ac269g.onrender.com'; 

let activeCaseId = null;
let currentUserRole = 'Officer';

// ==========================================
// 2. AUTHENTICATION & SESSION HANDLING
// ==========================================
async function processLogin(event) {
    event.preventDefault();
    const email = document.getElementById('staff-email').value;
    const password = document.getElementById('staff-password').value;
    const errorDiv = document.getElementById('login-error');
    errorDiv.innerText = '';

    try {
        const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include', // Important for cross-origin session cookies
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (!response.ok) {
            errorDiv.innerText = data.error || 'Authentication Failed.';
            return;
        }

        currentUserRole = data.role;
        document.getElementById('logged-user').innerText = `${data.email} (${data.role})`;
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('dashboard-screen').classList.remove('hidden');

        // Load dashboard data upon login
        await loadDashboardData();
    } catch (err) {
        errorDiv.innerText = 'Unable to connect to security server. Ensure Render API is online.';
        console.error('Login Error:', err);
    }
}

async function logOut() {
    try {
        await fetch(`${BACKEND_URL}/api/auth/logout`, {
            method: 'POST',
            credentials: 'include'
        });
    } catch (e) {
        console.warn('Logout notification failed:', e);
    }
    location.reload();
}

// ==========================================
// 3. DASHBOARD DATA SYNCHRONIZATION
// ==========================================
async function loadDashboardData() {
    try {
        const response = await fetch(`${BACKEND_URL}/api/dashboard/data`, {
            method: 'GET',
            credentials: 'include'
        });
        const data = await response.json();

        // Update statistical counters
        document.getElementById('total-cases-count').innerText = data.cases.length;
        document.getElementById('fraud-blocked-count').innerText = data.metrics.fraudBlockedCount;
        document.getElementById('mitigated-exposure-amount').innerText = 
            `$${data.metrics.mitigatedExposureAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })}`;

        // Update top hero alert card with the latest threat
        if (data.cases.length > 0) {
            const latest = data.cases[0];
            document.getElementById('alert-victim').innerText = `${latest.name} - ${latest.account}`;
            document.getElementById('alert-method').innerText = latest.vector || latest.description;
            document.getElementById('alert-percentage').innerText = `${latest.riskPercent}%`;
            document.getElementById('alert-time').innerText = 'Live Signal';
        } else {
            document.getElementById('alert-victim').innerText = 'Queue Clear';
            document.getElementById('alert-method').innerText = 'No Active Anomalies Detected';
            document.getElementById('alert-percentage').innerText = '0%';
        }

        // Render incident queue table
        const tbody = document.getElementById('table-rows');
        tbody.innerHTML = '';
        data.cases.forEach(c => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${c.id}</strong></td>
                <td>${c.name}<br><small style="color:var(--text-muted)">${c.account}</small></td>
                <td>${c.device}</td>
                <td>${c.location}</td>
                <td style="color:var(--color-warning); font-weight:600;">${c.amount}</td>
                <td><span class="badge-risk ${c.riskPercent > 90 ? 'critical' : ''}">${c.riskPercent}%</span></td>
                <td><span class="status-indicator">Action Required</span></td>
                <td>
                    <button class="btn-action-trigger" onclick='openIncidentModal(${JSON.stringify(c)})'>Review Case</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Populate System Operational Security Ledger (Audit Logs)
        const auditContainer = document.getElementById('audit-log-rows');
        if (auditContainer && data.auditLogs) {
            auditContainer.innerHTML = data.auditLogs.map(log => `<div>${log}</div>`).join('');
        }
    } catch (err) {
        console.error('Failed to sync dashboard:', err);
    }
}

// ==========================================
// 4. THREAT SIMULATION & RESOLUTION
// ==========================================
async function addNewSimulatedFraud() {
    try {
        await fetch(`${BACKEND_URL}/api/cases/simulate`, {
            method: 'POST',
            credentials: 'include'
        });
        await loadDashboardData();
    } catch (err) {
        alert('Simulation failed to trigger.');
    }
}

async function handleResolution(actionName, isFraud) {
    if (!activeCaseId) return;
    try {
        await fetch(`${BACKEND_URL}/api/cases/resolve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ caseId: activeCaseId, isFraud: isFraud })
        });
        closePopup();
        await loadDashboardData();
    } catch (err) {
        alert('Failed to transmit resolution matrix.');
    }
}

// ==========================================
// 5. MODAL & NAVIGATION CONTROLS
// ==========================================
function openIncidentModal(caseObj) {
    activeCaseId = caseObj.id;
    document.getElementById('pop-case-id').innerText = `Incident: ${caseObj.id}`;
    document.getElementById('pop-name').innerText = caseObj.name;
    document.getElementById('pop-acc').innerText = caseObj.account;
    document.getElementById('pop-amt').innerText = caseObj.amount;
    document.getElementById('pop-loc').innerText = caseObj.location;
    document.getElementById('pop-device').innerText = caseObj.device;
    document.getElementById('pop-desc').innerText = `${caseObj.vector ? '[' + caseObj.vector + '] ' : ''}${caseObj.description}`;
    
    document.getElementById('action-popup').classList.add('active');
}

function closePopup() {
    activeCaseId = null;
    document.getElementById('action-popup').classList.remove('active');
}

function checkAdminAccess() {
    const auditSection = document.getElementById('audit-log-section');
    if (currentUserRole !== 'Admin') {
        alert('Access Denied: The Security Operational Ledger requires Admin authorization. Sign in as admin@apexbank.com.');
        return;
    }
    auditSection.style.display = auditSection.style.display === 'none' ? 'block' : 'none';
}
