// Cyense Viewer - Main Application Logic

let scanData = null;
let filteredFindings = [];

// Searchable severity filter state (replaces the native <select>).
const SEVERITIES = [
    { value: 'all', label: 'All Severities' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'info', label: 'Info' },
];
let severityValue = 'all';

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    const scanId = getScanIdFromUrl();
    if (scanId) {
        loadScanData(scanId);
    } else {
        showError('No scan ID provided in URL');
    }

    // Set up event listeners
    document.getElementById('searchInput').addEventListener('input', applyFilters);

    // Searchable severity combobox
    initSeveritySelect();

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

// ---------------------------------------------------------------------------
// Searchable severity select (combobox with type-to-filter)
// ---------------------------------------------------------------------------
function initSeveritySelect() {
    const trigger = document.getElementById('severityTrigger');
    const menu = document.getElementById('severityMenu');
    const search = document.getElementById('severitySearch');
    const current = document.getElementById('severityCurrent');
    const options = document.getElementById('severityOptions');
    const count = document.getElementById('severityCount');

    function renderOptions(query) {
        const q = (query || '').trim().toLowerCase();
        const list = !q
            ? SEVERITIES
            : SEVERITIES.filter((s) => s.label.toLowerCase().includes(q));
        options.innerHTML = list.map((s) => `
            <button type="button" class="ssel-opt ${s.value === severityValue ? 'active' : ''}"
                    role="option" aria-selected="${s.value === severityValue}"
                    data-value="${s.value}">
                <span class="ssel-opt-label">${s.label}</span>
                ${s.value === severityValue ? '<span class="ssel-check">✓</span>' : ''}
            </button>
        `).join('')
        || '<div class="ssel-empty">Tidak ada hasil</div>';
        count.textContent = `${list.length} opsi`;
    }

    function openMenu() {
        menu.classList.add('open');
        scrollIntoViewIfNeeded(trigger);
        search.value = '';
        renderOptions('');
        search.focus();
    }
    function closeMenu() { menu.classList.remove('open'); }

    function choose(value) {
        severityValue = value;
        const s = SEVERITIES.find((x) => x.value === value) || SEVERITIES[0];
        current.textContent = s.label;
        closeMenu();
        applyFilters();
    }

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menu.classList.contains('open')) closeMenu();
        else openMenu();
    });
    menu.addEventListener('click', (e) => {
        const opt = e.target.closest('.ssel-opt');
        if (opt) { choose(opt.dataset.value); e.stopPropagation(); }
    });
    search.addEventListener('input', () => renderOptions(search.value));
    search.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMenu();
        if (e.key === 'Enter') e.preventDefault();
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            const opts = options.querySelectorAll('.ssel-opt');
            if (opts[0]) { opts[0].focus(); }
        }
    });
    options.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { search.focus(); closeMenu(); }
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            const opts = Array.from(options.querySelectorAll('.ssel-opt'));
            const idx = opts.indexOf(document.activeElement);
            const next = opts[(idx + (e.key === 'ArrowDown' ? 1 : opts.length - 1)) % opts.length];
            if (next) next.focus();
        }
        if (e.key === 'Enter' && document.activeElement.dataset?.value) {
            choose(document.activeElement.dataset.value);
        }
    });
    document.addEventListener('click', (e) => {
        if (!document.getElementById('severityWrap').contains(e.target)) closeMenu();
    });
}

// The viewer sticky header is sticky but not fixed; keep the menu inside viewport.
function scrollIntoViewIfNeeded(el) {
    const r = el.getBoundingClientRect();
    if (r.bottom > window.innerHeight - 80) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

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
    findingsPage = 1;

    // Render findings table
    renderFindingsTable(filteredFindings);
}

// ---------------------------------------------------------------------------
// Pagination (findings table + trajectory timeline)
// Keeps the DOM light on scans with hundreds/thousands of findings: only the
// current page's rows are rendered. Mirrors the Svelte UI's Pagination.svelte:
// windowed page numbers with ellipses, prev/next, rows-per-page selector.
// ---------------------------------------------------------------------------
let findingsPage = 1;
let findingsPageSize = 25;
const FINDINGS_SIZE_OPTIONS = [10, 25, 50, 100];

// Windowed page list with ellipses, e.g. [1,'…',4,5,6,'…',12].
function pageWindow(page, pages, span = 2) {
    const out = [];
    const lo = Math.max(1, page - span);
    const hi = Math.min(pages, page + span);
    if (lo > 1) { out.push(1); if (lo > 2) out.push('…'); }
    for (let i = lo; i <= hi; i++) out.push(i);
    if (hi < pages) { if (hi < pages - 1) out.push('…'); out.push(pages); }
    return out;
}

function pagerHtml(page, pageSize, total, sizes, navFn, sizeFn, unitLabel) {
    const pages = Math.max(1, Math.ceil((total || 0) / pageSize));
    if (pages <= 1) return '';
    const start = total ? (page - 1) * pageSize + 1 : 0;
    const end = Math.min(page * pageSize, total || 0);
    let html = `<div class="pager-info" aria-live="polite">Showing ${start}–${end} of ${total} ${unitLabel}</div>`;
    html += '<div class="pager-btns" role="group" aria-label="Page controls">';
    html += `<button type="button" class="pager-btn" ${page <= 1 ? 'disabled' : ''} aria-label="Previous page" onclick="${navFn}(${page - 1})">‹</button>`;
    for (const n of pageWindow(page, pages)) {
        if (n === '…') html += '<span class="pager-ellipsis" aria-hidden="true">…</span>';
        else html += `<button type="button" class="pager-btn ${n === page ? 'active' : ''}" ${n === page ? 'aria-current="page"' : ''} onclick="${navFn}(${n})">${n}</button>`;
    }
    html += `<button type="button" class="pager-btn" ${page >= pages ? 'disabled' : ''} aria-label="Next page" onclick="${navFn}(${page + 1})">›</button>`;
    html += '</div>';
    html += `<label class="pager-size">Per page <select class="pager-select" onchange="${sizeFn}(this.value)">`;
    for (const s of sizes) html += `<option value="${s}" ${s === pageSize ? 'selected' : ''}>${s}</option>`;
    html += '</select></label>';
    return html;
}

function gotoFindingsPage(p) {
    findingsPage = p;
    renderFindingsTable(filteredFindings);
    document.querySelector('.findings-table-container')
        ?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function setFindingsPageSize(v) {
    findingsPageSize = Number(v) || findingsPageSize;
    findingsPage = 1;
    renderFindingsTable(filteredFindings);
}

// Render findings table (current page only)
function renderFindingsTable(findings) {
    filteredFindings = findings || [];
    const tbody = document.getElementById('findingsTableBody');
    const pager = document.getElementById('findingsPager');

    if (filteredFindings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No findings found</td></tr>';
        if (pager) pager.innerHTML = '';
        return;
    }

    const pages = Math.max(1, Math.ceil(filteredFindings.length / findingsPageSize));
    if (findingsPage > pages) findingsPage = pages;
    const slice = filteredFindings.slice(
        (findingsPage - 1) * findingsPageSize, findingsPage * findingsPageSize);

    tbody.innerHTML = slice.map(finding => `
        <tr onclick="showFindingDetail('${escapeAttr(finding.finding_id)}')">
            <td>${escapeHtml(finding.finding_id)}</td>
            <td>${escapeHtml(finding.rule)}</td>
            <td><span class="severity-badge ${finding.severity}">${finding.severity.toUpperCase()}</span></td>
            <td>${fmtScore(finding.cvss_score)}</td>
            <td>${escapeHtml(finding.location || '-')}</td>
            <td>${escapeHtml(finding.title || '-')}</td>
        </tr>
    `).join('');

    if (pager) {
        pager.innerHTML = pagerHtml(findingsPage, findingsPageSize,
            filteredFindings.length, FINDINGS_SIZE_OPTIONS,
            'gotoFindingsPage', 'setFindingsPageSize', 'findings');
    }
}

// Apply filters (severity + search)
function applyFilters() {
    if (!scanData || !scanData.findings) return;

    const searchTerm = document.getElementById('searchInput').value.toLowerCase();

    filteredFindings = scanData.findings.filter(finding => {
        // Severity filter
        if (severityValue !== 'all' && finding.severity !== severityValue) {
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

    // New filter result set starts from page 1.
    findingsPage = 1;
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
            <div class="detail-value">${fmtScore(finding.cvss_score)}</div>
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
            <div class="detail-value">${fmtScore(finding.confidence * 100)}%</div>
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

// Escape a value for use inside a quoted HTML attribute (JavaScript string).
function escapeAttr(text) {
    return escapeHtml(String(text ?? '')).replace(/"/g, '&quot;');
}

// Safe CVSS score formatting — never assume the value is a number.
function fmtScore(score) {
    const n = Number(score);
    return Number.isFinite(n) ? n.toFixed(1) : '-';
}

function showError(message) {
    const tbody = document.getElementById('findingsTableBody');
    tbody.innerHTML = `<tr><td colspan="6" class="loading" style="color: var(--critical);">${escapeHtml(message)}</td></tr>`;
    const pager = document.getElementById('findingsPager');
    if (pager) pager.innerHTML = '';
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

// ---------------------------------------------------------------------------
// Trajectory timeline state — the step list can hold thousands of entries,
// so the timeline is paginated like the findings table.
// ---------------------------------------------------------------------------
let trajSteps = [];
let trajMinTime = 0;
let trajPage = 1;
let trajPageSize = 100;
const TRAJ_SIZE_OPTIONS = [50, 100, 250, 500];

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
        trajSteps = [];
        container.innerHTML = '<div class="no-data">No steps recorded in trajectories</div>';
        const pager = document.getElementById('trajPager');
        if (pager) pager.innerHTML = '';
        return;
    }

    trajSteps = allSteps;
    trajMinTime = allSteps[0].t || 0;
    trajPage = 1;
    const maxTime = allSteps[allSteps.length - 1].t || 0;
    const duration = maxTime - trajMinTime;

    // Build HTML: agent summary bar + duration header stay above the pager.
    let html = '';

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

    html += `<div class="trajectory-duration">`;
    html += `Duration: <strong>${duration.toFixed(2)}s</strong> · ${allSteps.length} steps · ${agentNames.length} agents`;
    html += '</div>';

    html += '<div class="timeline" id="trajTimeline"></div>';

    container.innerHTML = html;
    renderTrajectoryPage();
}

function renderTrajectoryPage() {
    const timeline = document.getElementById('trajTimeline');
    const pager = document.getElementById('trajPager');
    if (!timeline) return;

    const pages = Math.max(1, Math.ceil(trajSteps.length / trajPageSize));
    if (trajPage > pages) trajPage = pages;
    const slice = trajSteps.slice((trajPage - 1) * trajPageSize, trajPage * trajPageSize);

    timeline.innerHTML = slice.map((step) => {
        const icon = AGENT_ICONS[step.agent] || '🤖';
        const color = AGENT_COLORS[step.agent] || '#888';
        const elapsed = ((step.t || 0) - trajMinTime).toFixed(2);
        const action = step.action || 'unknown';
        const detail = step.detail || {};
        const detailKeys = Object.keys(detail);

        let html = `<div class="timeline-step" style="border-left-color: ${color}">`;
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
        return html;
    }).join('');

    if (pager) {
        pager.innerHTML = pagerHtml(trajPage, trajPageSize,
            trajSteps.length, TRAJ_SIZE_OPTIONS,
            'gotoTrajPage', 'setTrajPageSize', 'steps');
    }
}

function gotoTrajPage(p) {
    trajPage = p;
    renderTrajectoryPage();
    document.querySelector('.trajectories-section')
        ?.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

function setTrajPageSize(v) {
    trajPageSize = Number(v) || trajPageSize;
    trajPage = 1;
    renderTrajectoryPage();
}
