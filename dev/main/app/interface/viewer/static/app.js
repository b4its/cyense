// Cyense Viewer - Main Application Logic

let scanData = null;
let filteredFindings = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    const scanId = getScanIdFromUrl();
    if (scanId) {
        loadScanData(scanId);
    } else {
        showError('No scan ID provided in URL');
    }

    // Set up event listeners
    document.getElementById('severityFilter').addEventListener('change', applyFilters);
    document.getElementById('searchInput').addEventListener('input', applyFilters);
    
    // Modal close handlers
    const modal = document.getElementById('findingModal');
    const closeBtn = document.getElementsByClassName('close')[0];
    
    closeBtn.onclick = () => {
        modal.style.display = 'none';
    };
    
    window.onclick = (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    };
});

// Extract scan ID: server injects a meta tag; URL query param is a fallback
function getScanIdFromUrl() {
    const meta = document.querySelector('meta[name="scan-id"]');
    if (meta && meta.content) return meta.content;
    const params = new URLSearchParams(window.location.search);
    return params.get('scan_id');
}

// Load scan data from the viewer data endpoint (has disk fallback server-side)
async function loadScanData(scanId) {
    try {
        const response = await fetch(`/api/v1/viewer/${encodeURIComponent(scanId)}/data`);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        scanData = await response.json();

        if (scanData.message && (!scanData.findings || scanData.findings.length === 0)) {
            showError(scanData.message);
            renderScanData(); // still render header + zero counts
            return;
        }

        renderScanData();
        loadTrajectories(scanId);
    } catch (error) {
        console.error('Failed to load scan data:', error);
        showError(`Failed to load scan: ${error.message}`);
    }
}

// Render all scan data
function renderScanData() {
    if (!scanData) return;

    // Update header
    document.getElementById('scanId').textContent = scanData.scan_id;
    document.getElementById('scanDate').textContent = formatDate(scanData.created_at);

    // Update severity counts
    const summary = scanData.summary || {};
    document.getElementById('criticalCount').textContent = summary.critical || 0;
    document.getElementById('highCount').textContent = summary.high || 0;
    document.getElementById('mediumCount').textContent = summary.medium || 0;
    document.getElementById('lowCount').textContent = summary.low || 0;
    document.getElementById('infoCount').textContent = summary.info || 0;

    // Initialize filtered findings
    filteredFindings = scanData.findings || [];
    
    // Render findings table
    renderFindingsTable(filteredFindings);
}

// Render findings table
function renderFindingsTable(findings) {
    const tbody = document.getElementById('findingsTableBody');
    
    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No findings found</td></tr>';
        return;
    }

    tbody.innerHTML = findings.map(finding => `
        <tr onclick="showFindingDetail('${finding.finding_id}')">
            <td>${escapeHtml(finding.finding_id)}</td>
            <td>${escapeHtml(finding.rule)}</td>
            <td><span class="severity-badge ${finding.severity}">${finding.severity.toUpperCase()}</span></td>
            <td>${finding.cvss_score ? finding.cvss_score.toFixed(1) : '-'}</td>
            <td>${escapeHtml(finding.location || '-')}</td>
            <td>${escapeHtml(finding.title || '-')}</td>
        </tr>
    `).join('');
}

// Apply filters (severity + search)
function applyFilters() {
    if (!scanData || !scanData.findings) return;

    const severityFilter = document.getElementById('severityFilter').value;
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();

    filteredFindings = scanData.findings.filter(finding => {
        // Severity filter
        if (severityFilter !== 'all' && finding.severity !== severityFilter) {
            return false;
        }

        // Search filter
        if (searchTerm) {
            const searchFields = [
                finding.finding_id,
                finding.rule,
                finding.title,
                finding.description,
                finding.location,
                finding.cwe
            ].filter(Boolean).join(' ').toLowerCase();

            if (!searchFields.includes(searchTerm)) {
                return false;
            }
        }

        return true;
    });

    renderFindingsTable(filteredFindings);
}

// Show finding detail modal
function showFindingDetail(findingId) {
    const finding = scanData.findings.find(f => f.finding_id === findingId);
    if (!finding) return;

    const modal = document.getElementById('findingModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    modalTitle.textContent = `${finding.rule}: ${finding.title || 'Untitled'}`;

    modalBody.innerHTML = `
        <div class="detail-row">
            <div class="detail-label">Finding ID</div>
            <div class="detail-value">${escapeHtml(finding.finding_id)}</div>
        </div>
        
        <div class="detail-row">
            <div class="detail-label">Rule</div>
            <div class="detail-value">${escapeHtml(finding.rule)}</div>
        </div>
        
        <div class="detail-row">
            <div class="detail-label">Severity</div>
            <div class="detail-value">
                <span class="severity-badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
            </div>
        </div>
        
        ${finding.cvss_score ? `
        <div class="detail-row">
            <div class="detail-label">CVSS Score</div>
            <div class="detail-value">${finding.cvss_score.toFixed(1)}</div>
        </div>
        ` : ''}
        
        ${finding.cvss_vector ? `
        <div class="detail-row">
            <div class="detail-label">CVSS Vector</div>
            <div class="detail-value cvss-vector">${escapeHtml(finding.cvss_vector)}</div>
        </div>
        ` : ''}
        
        ${finding.cwe ? `
        <div class="detail-row">
            <div class="detail-label">CWE</div>
            <div class="detail-value">${escapeHtml(finding.cwe)}</div>
        </div>
        ` : ''}
        
        ${finding.location ? `
        <div class="detail-row">
            <div class="detail-label">Location</div>
            <div class="detail-value">${escapeHtml(finding.location)}</div>
        </div>
        ` : ''}
        
        ${finding.description ? `
        <div class="detail-row">
            <div class="detail-label">Description</div>
            <div class="detail-value">${escapeHtml(finding.description)}</div>
        </div>
        ` : ''}
        
        ${finding.evidence ? `
        <div class="detail-row">
            <div class="detail-label">Evidence</div>
            <div class="detail-value">
                <pre class="code-block">${escapeHtml(JSON.stringify(finding.evidence, null, 2))}</pre>
            </div>
        </div>
        ` : ''}
        
        ${finding.remediation ? `
        <div class="detail-row">
            <div class="detail-label">Remediation</div>
            <div class="detail-value">${escapeHtml(finding.remediation)}</div>
        </div>
        ` : ''}
        
        ${finding.confidence ? `
        <div class="detail-row">
            <div class="detail-label">Confidence</div>
            <div class="detail-value">${(finding.confidence * 100).toFixed(0)}%</div>
        </div>
        ` : ''}
    `;

    modal.style.display = 'block';
}

// Helper functions
function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    try {
        const date = new Date(dateString);
        return date.toLocaleString();
    } catch {
        return dateString;
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showError(message) {
    const tbody = document.getElementById('findingsTableBody');
    tbody.innerHTML = `<tr><td colspan="6" class="loading" style="color: var(--critical);">${escapeHtml(message)}</td></tr>`;
}

// ---------------------------------------------------------------------------
// Agent Trajectory Visualization (Strix-inspired agent graph)
// ---------------------------------------------------------------------------

const AGENT_ICONS = {
    recon: '🎯',
    prober: '🕵️',
    verifier: '⚖️',
    fetcher: '🐙',
    fixer: '🔧',
    brain: '🧠',
    crawler: '🕸️',
    orchestrator: '🎼',
};

const AGENT_COLORS = {
    recon: '#4a9eff',
    prober: '#ff9f43',
    verifier: '#2ed573',
    fetcher: '#a55eea',
    fixer: '#ff6b6b',
    brain: '#ffd93d',
    crawler: '#6c5ce7',
    orchestrator: '#00cec9',
};

async function loadTrajectories(scanId) {
    const container = document.getElementById('trajectoriesContainer');
    if (!container) return;

    try {
        const response = await fetch(`/api/v1/viewer/${encodeURIComponent(scanId)}/trajectories`);
        if (!response.ok) {
            container.innerHTML = '<div class="no-data">No trajectory data available</div>';
            return;
        }

        const data = await response.json();
        const agents = data.agents || {};

        if (Object.keys(agents).length === 0) {
            container.innerHTML = '<div class="no-data">No agent trajectories recorded for this scan</div>';
            return;
        }

        renderTrajectories(agents);
    } catch (error) {
        console.error('Failed to load trajectories:', error);
        container.innerHTML = '<div class="no-data">Failed to load trajectory data</div>';
    }
}

function renderTrajectories(agents) {
    const container = document.getElementById('trajectoriesContainer');

    // Collect all steps across all agents and sort by timestamp
    const allSteps = [];
    for (const [agentName, trajData] of Object.entries(agents)) {
        const steps = trajData.steps || [];
        for (const step of steps) {
            allSteps.push({
                agent: agentName,
                ...step,
            });
        }
    }

    // Sort by timestamp
    allSteps.sort((a, b) => (a.t || 0) - (b.t || 0));

    if (allSteps.length === 0) {
        container.innerHTML = '<div class="no-data">No steps recorded in trajectories</div>';
        return;
    }

    const minTime = allSteps[0].t || 0;
    const maxTime = allSteps[allSteps.length - 1].t || 0;
    const duration = maxTime - minTime;

    // Build HTML
    let html = '';

    // Agent summary bar
    html += '<div class="agent-summary">';
    const agentNames = Object.keys(agents);
    for (const name of agentNames) {
        const icon = AGENT_ICONS[name] || '🤖';
        const color = AGENT_COLORS[name] || '#888';
        const stepCount = (agents[name].steps || []).length;
        html += `<span class="agent-badge" style="border-color: ${color}">`;
        html += `<span class="agent-icon">${icon}</span>`;
        html += `<span class="agent-name">${escapeHtml(name)}</span>`;
        html += `<span class="agent-steps">${stepCount}</span>`;
        html += '</span>';
    }
    html += '</div>';

    // Duration info
    html += `<div class="trajectory-duration">`;
    html += `Duration: <strong>${duration.toFixed(2)}s</strong> · ${allSteps.length} steps · ${agentNames.length} agents`;
    html += '</div>';

    // Timeline
    html += '<div class="timeline">';
    for (const step of allSteps) {
        const icon = AGENT_ICONS[step.agent] || '🤖';
        const color = AGENT_COLORS[step.agent] || '#888';
        const elapsed = ((step.t || 0) - minTime).toFixed(2);
        const action = step.action || 'unknown';
        const detail = step.detail || {};
        const detailKeys = Object.keys(detail);

        html += `<div class="timeline-step" style="border-left-color: ${color}">`;
        html += `<div class="step-header">`;
        html += `<span class="step-icon" style="background: ${color}22; color: ${color}">${icon}</span>`;
        html += `<span class="step-agent" style="color: ${color}">${escapeHtml(step.agent)}</span>`;
        html += `<span class="step-action">${escapeHtml(action)}</span>`;
        html += `<span class="step-time">t+${elapsed}s</span>`;
        html += '</div>';

        if (detailKeys.length > 0) {
            html += '<div class="step-detail">';
            for (const key of detailKeys.slice(0, 5)) {
                const val = detail[key];
                const displayVal = typeof val === 'object'
                    ? JSON.stringify(val).slice(0, 100)
                    : String(val).slice(0, 100);
                html += `<span class="detail-item"><span class="detail-key">${escapeHtml(key)}</span>: <span class="detail-val">${escapeHtml(displayVal)}</span></span>`;
            }
            if (detailKeys.length > 5) {
                html += `<span class="detail-more">+${detailKeys.length - 5} more</span>`;
            }
            html += '</div>';
        }

        html += '</div>';
    }
    html += '</div>';

    container.innerHTML = html;
}
