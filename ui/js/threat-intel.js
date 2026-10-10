
'use strict';

/* ============================================================
   MY SIEM — THREAT INTELLIGENCE
   Real backend data only. No fabricated threat intelligence.
   ============================================================ */

const DEFAULT_API = 'http://100.90.174.77:5000';
const PAGE_SIZE = 10;
const REFRESH_INTERVAL = 15000;

let allThreats = [];
let filteredThreats = [];
let currentPage = 1;
let severityChart = null;
let typeChart = null;
let liveTimer = null;
let liveEnabled = true;

function getApiBase() {
    const configured = window.SIEM_API_BASE;

    if (typeof configured === 'string' && configured.trim()) {
        return configured.trim().replace(/\/+$/, '');
    }

    if (window.location.protocol === 'file:') {
        return DEFAULT_API;
    }

    return window.location.origin.replace(/\/+$/, '');
}

const API_BASE = getApiBase();

/* ---------- Helpers ---------- */

function escapeHTML(value) {
    const element = document.createElement('div');
    element.textContent = value == null ? '' : String(value);
    return element.innerHTML;
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function normalizeSeverity(value) {
    const valueUpper = String(value || 'INFO').trim().toUpperCase();

    const aliases = {
        SEV1: 'CRITICAL',
        SEV2: 'HIGH',
        SEV3: 'MEDIUM',
        SEV4: 'LOW',
        WARNING: 'MEDIUM',
        INFORMATIONAL: 'INFO'
    };

    const severity = aliases[valueUpper.replace(/[-\s]/g, '')] || valueUpper;

    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)
        ? severity
        : 'INFO';
}

function normalizeStatus(value) {
    const raw = String(value || 'OPEN')
        .trim()
        .toUpperCase()
        .replace(/[\s-]+/g, '_');

    const aliases = {
        NEW: 'OPEN',
        ACTIVE: 'OPEN',
        PENDING: 'OPEN',
        IN_PROGRESS: 'IN_PROGRESS',
        INVESTIGATION: 'INVESTIGATING',
        PATCHED: 'RESOLVED',
        MITIGATED: 'RESOLVED',
        NEUTRALIZED: 'RESOLVED'
    };

    return aliases[raw] || raw;
}

function statusLabel(status) {
    const labels = {
        OPEN: 'OPEN',
        ACTIVE: 'ACTIVE',
        IN_PROGRESS: 'IN PROGRESS',
        INVESTIGATING: 'INVESTIGATING',
        CONTAINED: 'CONTAINED',
        RESOLVED: 'RESOLVED',
        CLOSED: 'CLOSED',
        FALSE_POSITIVE: 'FALSE POSITIVE'
    };

    return labels[status] || status || 'UNKNOWN';
}

function severityColor(severity) {
    const colors = {
        CRITICAL: '#EF4444',
        HIGH: '#FF9F43',
        MEDIUM: '#FACC15',
        LOW: '#22C55E',
        INFO: '#4D9FFF'
    };

    return colors[severity] || '#8A9BB5';
}

function getTimestamp(alert) {
    return alert.timestamp ??
        alert.received_at ??
        alert.created_at ??
        alert.detected_at ??
        alert.time ??
        null;
}

function timestampValue(value) {
    if (!value) return 0;

    const parsed = new Date(value).getTime();
    return Number.isNaN(parsed) ? 0 : parsed;
}

function formatDate(value) {
    if (!value) return 'N/A';

    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleString();
}

function getSeverityRank(severity) {
    const ranks = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3,
        INFO: 4
    };

    return ranks[severity] ?? 99;
}

function isActiveStatus(status) {
    return ['OPEN', 'ACTIVE', 'IN_PROGRESS', 'INVESTIGATING', 'CONTAINED']
        .includes(status);
}

function isResolvedStatus(status) {
    return ['RESOLVED', 'CLOSED', 'FALSE_POSITIVE'].includes(status);
}

async function apiGet(endpoint) {
    const url = `${API_BASE}${endpoint}`;
    console.log('[Threat Intel] GET:', url);

    const response = await fetch(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        cache: 'no-store'
    });

    const contentType = response.headers.get('content-type') || '';
    let data;

    if (contentType.includes('application/json')) {
        data = await response.json();
    } else {
        data = await response.text();
    }

    if (!response.ok) {
        const message = typeof data === 'object' && data
            ? data.error || data.message || `HTTP ${response.status}`
            : `HTTP ${response.status}`;

        throw new Error(message);
    }

    return data;
}

function extractAlerts(data) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.alerts)) return data.alerts;
    if (data && Array.isArray(data.data)) return data.data;
    if (data && Array.isArray(data.results)) return data.results;

    throw new Error('The /api/alerts endpoint did not return an alert array.');
}

/* ---------- Build intelligence from real alerts ---------- */

function buildThreats(alerts) {
    const groups = new Map();

    alerts.forEach((alert, index) => {
        if (!alert || typeof alert !== 'object') return;

        const name = String(
            alert.alert_type ??
            alert.rule_name ??
            alert.event_type ??
            alert.type ??
            alert.title ??
            'Unknown Alert'
        ).trim() || 'Unknown Alert';

        const severity = normalizeSeverity(
            alert.severity ?? alert.level ?? alert.priority
        );

        const status = normalizeStatus(alert.status ?? alert.state);
        const timestamp = getTimestamp(alert);

        if (!groups.has(name)) {
            groups.set(name, {
                id: String(
                    alert.alert_type_id ??
                    alert.rule_id ??
                    alert.id ??
                    `alert-type-${index + 1}`
                ),
                name,
                category: name,
                severity,
                status,
                description: String(
                    alert.description ??
                    alert.message ??
                    alert.details ??
                    'No description supplied by the backend.'
                ),
                count: 0,
                firstSeen: timestamp,
                lastSeen: timestamp,
                sourceIPs: [],
                agents: [],
                rules: [],
                statuses: [],
                rawAlerts: []
            });
        }

        const threat = groups.get(name);
        threat.count += 1;
        threat.rawAlerts.push(alert);

        if (getSeverityRank(severity) < getSeverityRank(threat.severity)) {
            threat.severity = severity;
        }

        if (timestamp) {
            if (
                !threat.firstSeen ||
                timestampValue(timestamp) < timestampValue(threat.firstSeen)
            ) {
                threat.firstSeen = timestamp;
            }

            if (
                !threat.lastSeen ||
                timestampValue(timestamp) > timestampValue(threat.lastSeen)
            ) {
                threat.lastSeen = timestamp;
                threat.status = status;

                threat.description = String(
                    alert.description ??
                    alert.message ??
                    alert.details ??
                    threat.description
                );
            }
        }

        threat.statuses.push(status);

        const sourceIP = alert.source_ip ??
            alert.src_ip ??
            alert.sourceIp ??
            alert.src ??
            null;

        const agent = alert.agent_id ??
            alert.agent ??
            alert.hostname ??
            alert.host ??
            null;

        const rule = alert.rule_id ??
            alert.rule_name ??
            alert.rule ??
            null;

        if (sourceIP && !threat.sourceIPs.includes(String(sourceIP))) {
            threat.sourceIPs.push(String(sourceIP));
        }

        if (agent && !threat.agents.includes(String(agent))) {
            threat.agents.push(String(agent));
        }

        if (rule && !threat.rules.includes(String(rule))) {
            threat.rules.push(String(rule));
        }
    });

    return Array.from(groups.values()).sort((a, b) => {
        const severityDifference =
            getSeverityRank(a.severity) - getSeverityRank(b.severity);

        if (severityDifference !== 0) return severityDifference;

        return timestampValue(b.lastSeen) - timestampValue(a.lastSeen);
    });
}

/* ---------- Load backend data ---------- */

async function loadThreatIntel(options = {}) {
    const tbody = document.getElementById('threatsBody');
    const silent = options.silent === true;

    if (!silent && tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="loading-text">
                    <i class="fas fa-spinner fa-spin text-green"></i>
                    Loading real SIEM alerts...
                </td>
            </tr>`;
    }

    const refreshIcon = document.getElementById('refreshIcon');
    if (refreshIcon) refreshIcon.classList.add('fa-spin');

    try {
        const response = await apiGet('/api/alerts');
        const alerts = extractAlerts(response);

        allThreats = buildThreats(alerts);
        currentPage = 1;

        updateStats();
        updateTypeFilter();
        applyFilters();
        renderCharts();
        updateAPIStatus(true);
        updateLastUpdated();

        console.log(
            `[Threat Intel] Loaded ${alerts.length} real alerts; ` +
            `${allThreats.length} alert types.`
        );
    } catch (error) {
        console.error('[Threat Intel] API error:', error);

        allThreats = [];
        filteredThreats = [];
        currentPage = 1;

        updateStats();
        updateTypeFilter();
        renderCharts();
        renderThreats();
        updatePagination();
        updateAPIStatus(false, error.message);
        updateLastUpdated();

        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8">
                        <div style="padding:24px;text-align:left">
                            <div style="color:#EF4444;font-size:18px;margin-bottom:8px">
                                <i class="fas fa-triangle-exclamation"></i>
                                Threat intelligence API unavailable
                            </div>
                            <p style="color:var(--text-secondary)">
                                ${escapeHTML(error.message)}
                            </p>
                            <p style="color:var(--text-secondary);font-size:12px">
                                API: ${escapeHTML(API_BASE)}/api/alerts
                            </p>
                            <button class="filter-btn" type="button"
                                    onclick="loadThreatIntel()">
                                <i class="fas fa-rotate"></i> Retry
                            </button>
                        </div>
                    </td>
                </tr>`;
        }
    } finally {
        if (refreshIcon) refreshIcon.classList.remove('fa-spin');
    }
}

/* ---------- Statistics ---------- */

function updateStats() {
    setText('threatTotal', allThreats.length);

    setText(
        'threatCritical',
        allThreats.filter(item => item.severity === 'CRITICAL').length
    );

    setText(
        'threatHigh',
        allThreats.filter(item => item.severity === 'HIGH').length
    );

    setText(
        'threatActive',
        allThreats.filter(item => isActiveStatus(item.status)).length
    );

    // This card displays resolved/closed alert types, not malware counts.
    setText(
        'threatPatched',
        allThreats.filter(item => isResolvedStatus(item.status)).length
    );

    // Backwards compatibility with the older HTML ID.
    setText(
        'threatMalware',
        allThreats.filter(item => isResolvedStatus(item.status)).length
    );

    const alertBadge = document.getElementById('alertBadge');
    if (alertBadge) {
        alertBadge.textContent = allThreats.filter(item =>
            ['CRITICAL', 'HIGH'].includes(item.severity) &&
            isActiveStatus(item.status)
        ).length;
    }
}

/* ---------- Dynamic type filter ---------- */

function updateTypeFilter() {
    const select = document.getElementById('typeFilter');
    if (!select) return;

    const previousValue = select.value || 'ALL';
    const types = [...new Set(allThreats.map(item => item.category))].sort();

    select.innerHTML = '<option value="ALL">All Types</option>';

    types.forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type;
        select.appendChild(option);
    });

    select.value = types.includes(previousValue) ? previousValue : 'ALL';
}

/* ---------- Filters and search ---------- */

function applyFilters() {
    const search = (
        document.getElementById('searchInput')?.value || ''
    ).trim().toLowerCase();

    const severity = document.getElementById('severityFilter')?.value || 'ALL';
    const status = document.getElementById('statusFilter')?.value || 'ALL';
    const type = document.getElementById('typeFilter')?.value || 'ALL';

    filteredThreats = allThreats.filter(threat => {
        const searchText = [
            threat.name,
            threat.category,
            threat.severity,
            threat.status,
            threat.description,
            ...threat.sourceIPs,
            ...threat.agents,
            ...threat.rules
        ].join(' ').toLowerCase();

        const matchesSearch = !search || searchText.includes(search);
        const matchesSeverity =
            severity === 'ALL' || threat.severity === severity;

        let matchesStatus = status === 'ALL';

        if (status === 'Active') {
            matchesStatus = isActiveStatus(threat.status);
        } else if (status === 'Patched') {
            matchesStatus = isResolvedStatus(threat.status);
        } else if (status === 'Dormant') {
            matchesStatus = !isActiveStatus(threat.status) &&
                !isResolvedStatus(threat.status);
        } else if (!matchesStatus) {
            matchesStatus = threat.status === normalizeStatus(status);
        }

        const matchesType = type === 'ALL' || threat.category === type;

        return matchesSearch && matchesSeverity && matchesStatus && matchesType;
    });

    currentPage = 1;
    renderThreats();
    updatePagination();
}

function searchThreats() {
    applyFilters();
}

function filterBySeverity(value) {
    const select = document.getElementById('severityFilter');
    if (select) select.value = value || 'ALL';
    applyFilters();
}

function filterByStatus(value) {
    const select = document.getElementById('statusFilter');
    if (select) select.value = value || 'ALL';
    applyFilters();
}

function resetFilters() {
    ['searchInput'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = '';
    });

    ['severityFilter', 'statusFilter', 'typeFilter'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = 'ALL';
    });

    applyFilters();
}

/* ---------- Threat table ---------- */

function renderThreats() {
    const tbody = document.getElementById('threatsBody');
    if (!tbody) return;

    const start = (currentPage - 1) * PAGE_SIZE;
    const rows = filteredThreats.slice(start, start + PAGE_SIZE);

    if (!rows.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8">
                    <div style="padding:28px;text-align:left">
                        <div style="color:var(--green);font-size:18px;margin-bottom:8px">
                            <i class="fas fa-shield-alt"></i> No matching alert types
                        </div>
                        <p style="color:var(--text-secondary)">
                            No backend alert records match the selected filters.
                        </p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = rows.map((threat, index) => {
        const rowIndex = start + index;
        const detailId = `detail-${rowIndex}`;
        const severity = escapeHTML(threat.severity);
        const status = escapeHTML(threat.status);
        const sourceIPs = threat.sourceIPs.length
            ? threat.sourceIPs.map(escapeHTML).join(', ')
            : 'N/A';

        const agents = threat.agents.length
            ? threat.agents.map(escapeHTML).join(', ')
            : 'N/A';

        const rules = threat.rules.length
            ? threat.rules.map(escapeHTML).join(', ')
            : 'N/A';

        return `
            <tr>
                <td>
                    <button class="expand-btn" type="button"
                            aria-label="Show details"
                            onclick="toggleDetail('${detailId}')">
                        <i id="icon-${detailId}" class="fas fa-chevron-down"></i>
                    </button>
                </td>
                <td>
                    <strong style="color:${severityColor(threat.severity)}">
                        ${escapeHTML(threat.name)}
                    </strong>
                    <div style="margin-top:4px;font-size:10px;color:var(--text-secondary)">
                        ${threat.count} occurrence${threat.count === 1 ? '' : 's'}
                    </div>
                </td>
                <td><span class="badge">${escapeHTML(threat.category)}</span></td>
                <td>
                    <span class="badge badge-${severity}">${severity}</span>
                </td>
                <td style="font-size:11px;color:var(--text-secondary)">
                    ${sourceIPs}
                </td>
                <td>
                    <span class="badge badge-${status}">
                        ${escapeHTML(statusLabel(threat.status))}
                    </span>
                </td>
                <td style="font-size:10px;color:var(--text-secondary)">
                    ${escapeHTML(formatDate(threat.firstSeen))}
                </td>
                <td>
                    <button class="filter-btn" type="button"
                            onclick="toggleDetail('${detailId}')">
                        <i class="fas fa-eye"></i> Details
                    </button>
                </td>
            </tr>
            <tr id="${detailId}" style="display:none">
                <td colspan="8">
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="label">Description</span>
                            <span class="value">${escapeHTML(threat.description)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Source IPs</span>
                            <span class="value">${sourceIPs}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Endpoints</span>
                            <span class="value">${agents}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Rule IDs</span>
                            <span class="value">${rules}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Occurrences</span>
                            <span class="value">${threat.count}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Current Status</span>
                            <span class="value">${escapeHTML(statusLabel(threat.status))}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">First Seen</span>
                            <span class="value">${escapeHTML(formatDate(threat.firstSeen))}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Last Seen</span>
                            <span class="value">${escapeHTML(formatDate(threat.lastSeen))}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Threat Actor / CVE</span>
                            <span class="value">Not provided by the current alerts API</span>
                        </div>
                    </div>
                </td>
            </tr>`;
    }).join('');
}

function toggleDetail(id) {
    const row = document.getElementById(id);
    const icon = document.getElementById(`icon-${id}`);
    if (!row) return;

    const isHidden = row.style.display === 'none' || row.style.display === '';
    row.style.display = isHidden ? 'table-row' : 'none';

    if (icon) {
        icon.className = isHidden
            ? 'fas fa-chevron-up'
            : 'fas fa-chevron-down';
    }
}

/* ---------- Pagination ---------- */

function updatePagination() {
    const total = filteredThreats.length;
    const totalPages = Math.ceil(total / PAGE_SIZE);

    setText(
        'pageInfo',
        total === 0
            ? 'Showing 0 threats'
            : `Showing ${Math.min((currentPage - 1) * PAGE_SIZE + 1, total)}–${Math.min(currentPage * PAGE_SIZE, total)} of ${total}`
    );

    const previous = document.getElementById('prevPage');
    const next = document.getElementById('nextPage');

    if (previous) previous.disabled = currentPage <= 1;
    if (next) next.disabled = totalPages === 0 || currentPage >= totalPages;
}

function changePage(direction) {
    const totalPages = Math.ceil(filteredThreats.length / PAGE_SIZE);
    const nextPage = currentPage + Number(direction);

    if (nextPage < 1 || nextPage > totalPages) return;

    currentPage = nextPage;
    renderThreats();
    updatePagination();
}

function nextPage() {
    changePage(1);
}

function prevPage() {
    changePage(-1);
}

/* ---------- Charts ---------- */

function renderCharts() {
    renderSeverityChart();
    renderTypeChart();
}

function getChartTextColor() {
    return getComputedStyle(document.body)
        .getPropertyValue('--text-secondary').trim() || '#8A9BB5';
}

function renderSeverityChart() {
    const canvas = document.getElementById('severityChart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (severityChart) {
        severityChart.destroy();
        severityChart = null;
    }

    const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const values = labels.map(severity =>
        allThreats.filter(item => item.severity === severity)
            .reduce((sum, item) => sum + item.count, 0)
    );

    severityChart = new Chart(canvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: labels.map(severity => severityColor(severity)),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: getChartTextColor(),
                        padding: 12,
                        font: { size: 10 }
                    }
                }
            }
        }
    });
}

function renderTypeChart() {
    const canvas = document.getElementById('typeChart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (typeChart) {
        typeChart.destroy();
        typeChart = null;
    }

    const counts = {};

    allThreats.forEach(threat => {
        counts[threat.name] = (counts[threat.name] || 0) + threat.count;
    });

    const sorted = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);

    const labels = sorted.length ? sorted.map(item => item[0]) : ['No Data'];
    const values = sorted.length ? sorted.map(item => item[1]) : [0];

    typeChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Real alert occurrences',
                data: values,
                backgroundColor: [
                    '#EF4444', '#FF9F43', '#38BDF8', '#00E5A0',
                    '#A855F7', '#FACC15', '#14B8A6', '#F97316'
                ],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: getChartTextColor(), precision: 0 },
                    grid: { color: 'rgba(255,255,255,0.06)' }
                },
                x: {
                    ticks: {
                        color: getChartTextColor(),
                        font: { size: 9 }
                    },
                    grid: { display: false }
                }
            }
        }
    });
}

/* ---------- CSV export ---------- */

function exportThreatsCSV() {
    if (!filteredThreats.length) {
        alert('There are no threat records to export.');
        return;
    }

    const headers = [
        'Alert Type',
        'Category',
        'Severity',
        'Status',
        'Source IPs',
        'Endpoints',
        'Rule IDs',
        'Occurrences',
        'First Seen',
        'Last Seen',
        'Description'
    ];

    const quote = value =>
        `"${String(value ?? '').replace(/"/g, '""')}"`;

    const rows = [
        headers,
        ...filteredThreats.map(item => [
            item.name,
            item.category,
            item.severity,
            item.status,
            item.sourceIPs.join('; '),
            item.agents.join('; '),
            item.rules.join('; '),
            item.count,
            item.firstSeen || '',
            item.lastSeen || '',
            item.description
        ])
    ];

    const csv = '\uFEFF' + rows
        .map(row => row.map(quote).join(','))
        .join('\r\n');

    const blob = new Blob([csv], {
        type: 'text/csv;charset=utf-8;'
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = `siem-threat-intel-${new Date().toISOString().slice(0, 10)}.csv`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}

function exportThreats() {
    exportThreatsCSV();
}

/* ---------- API status ---------- */

function updateAPIStatus(online, message = '') {
    const badge = document.getElementById('liveApi');
    if (badge) {
        badge.textContent = online ? 'LIVE API' : 'API ERROR';
        badge.style.color = online ? '#00E5A0' : '#EF4444';
    }

    const status = document.getElementById('statusBarRight');

    if (status) {
        status.textContent = online
            ? `API connected · Last scan: ${new Date().toLocaleTimeString()}`
            : `API unavailable · ${message || 'Check backend connection'}`;

        status.style.color = online ? '#22C55E' : '#EF4444';
    }

    const liveBadge = document.getElementById('liveBadge');

    if (liveBadge) {
        liveBadge.title = online
            ? 'Connected to the SIEM alerts API'
            : 'Could not connect to the SIEM alerts API';
    }
}

function updateLastUpdated() {
    setText('lastUpdate', `Last updated: ${new Date().toLocaleTimeString()}`);
}

/* ---------- Live refresh ---------- */

function startLiveRefresh() {
    stopLiveRefresh();

    if (!liveEnabled) return;

    liveTimer = setInterval(() => {
        if (!document.hidden) {
            loadThreatIntel({ silent: true });
        }
    }, REFRESH_INTERVAL);
}

function stopLiveRefresh() {
    if (liveTimer) {
        clearInterval(liveTimer);
        liveTimer = null;
    }
}

function toggleLive() {
    liveEnabled = !liveEnabled;

    const label = document.getElementById('liveLabel');
    if (label) label.textContent = liveEnabled ? 'LIVE' : 'PAUSED';

    if (liveEnabled) {
        startLiveRefresh();
        loadThreatIntel();
    } else {
        stopLiveRefresh();
    }
}

/* ---------- Theme ---------- */

function loadTheme() {
    let theme = 'dark';

    try {
        theme = localStorage.getItem('siem_theme') || 'dark';
    } catch (_) {}

    const body = document.body;
    const label = document.getElementById('themeLabel');
    const icon = document.getElementById('themeToggle')?.querySelector('i');

    if (theme === 'light') {
        body.setAttribute('data-theme', 'light');
        if (label) label.textContent = 'Light';
        if (icon) icon.className = 'fas fa-sun';
    } else {
        body.removeAttribute('data-theme');
        if (label) label.textContent = 'Dark';
        if (icon) icon.className = 'fas fa-moon';
    }
}

function toggleTheme() {
    const isLight = document.body.getAttribute('data-theme') === 'light';
    const nextTheme = isLight ? 'dark' : 'light';

    if (nextTheme === 'light') {
        document.body.setAttribute('data-theme', 'light');
    } else {
        document.body.removeAttribute('data-theme');
    }

    try {
        localStorage.setItem('siem_theme', nextTheme);
    } catch (_) {}

    loadTheme();
    renderCharts();
}

/* ---------- Initialization ---------- */

function setupListeners() {
    document.getElementById('searchInput')
        ?.addEventListener('input', searchThreats);

    document.getElementById('severityFilter')
        ?.addEventListener('change', searchThreats);

    document.getElementById('statusFilter')
        ?.addEventListener('change', searchThreats);

    document.getElementById('typeFilter')
        ?.addEventListener('change', searchThreats);

    document.getElementById('prevPage')
        ?.addEventListener('click', () => changePage(-1));

    document.getElementById('nextPage')
        ?.addEventListener('click', () => changePage(1));

    document.getElementById('threatModal')
        ?.addEventListener('click', event => {
            if (event.target.id === 'threatModal') {
                event.currentTarget.style.display = 'none';
            }
        });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
            const modal = document.getElementById('threatModal');
            if (modal) modal.style.display = 'none';
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('[MY SIEM] Threat Intelligence');
    console.log('[MY SIEM] Real backend data mode');
    console.log('[MY SIEM] API:', API_BASE);

    loadTheme();
    setupListeners();
    loadThreatIntel();
    startLiveRefresh();
});

/* ---------- Public functions for HTML handlers ---------- */

window.loadThreatIntel = loadThreatIntel;
window.searchThreats = searchThreats;
window.applyFilters = applyFilters;
window.filterBySeverity = filterBySeverity;
window.filterByStatus = filterByStatus;
window.resetFilters = resetFilters;
window.changePage = changePage;
window.nextPage = nextPage;
window.prevPage = prevPage;
window.toggleDetail = toggleDetail;
window.toggleLive = toggleLive;
window.toggleTheme = toggleTheme;
window.loadTheme = loadTheme;
window.exportThreats = exportThreats;
window.exportThreatsCSV = exportThreatsCSV;

window.addEventListener('beforeunload', () => {
    stopLiveRefresh();

    if (severityChart) severityChart.destroy();
    if (typeChart) typeChart.destroy();
});
