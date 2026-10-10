
'use strict';

/* ============================================================
   MY SIEM — ALERTS & DETECTIONS
   Real backend data only. No demo records.
   ============================================================ */

(() => {
    const API_BASE = String(
        window.SIEM_API_BASE || 'http://100.90.174.77:5000'
    ).replace(/\/+$/, '');

    const PAGE_SIZE = 10;
    const REFRESH_MS = 15000;

    let allAlerts = [];
    let filteredAlerts = [];
    let currentPage = 1;
    let liveEnabled = true;
    let refreshTimer = null;
    let loading = false;
    let lastSuccess = null;
    let requestController = null;

    const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    // ------------------------------------------------------------
    // HELPERS
    // ------------------------------------------------------------

    function byId(id) {
        return document.getElementById(id);
    }

    function setText(id, value) {
        const element = byId(id);
        if (element) element.textContent = String(value ?? '');
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function firstValue(record, keys) {
        for (const key of keys) {
            const value = record?.[key];
            if (
                value !== undefined &&
                value !== null &&
                String(value).trim() !== ''
            ) {
                return value;
            }
        }
        return null;
    }

    function apiUrl(path) {
        return `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
    }

    async function fetchAlerts() {
        if (requestController) requestController.abort();

        requestController = new AbortController();
        const timeout = setTimeout(() => requestController?.abort(), 12000);

        try {
            const response = await fetch(apiUrl('/api/alerts'), {
                method: 'GET',
                headers: { Accept: 'application/json' },
                cache: 'no-store',
                signal: requestController.signal
            });

            if (!response.ok) {
                throw new Error(`API returned HTTP ${response.status}`);
            }

            const type = response.headers.get('content-type') || '';
            if (!type.includes('application/json')) {
                throw new Error('The alerts API did not return JSON.');
            }

            const payload = await response.json();
            return extractAlertArray(payload);
        } finally {
            clearTimeout(timeout);
        }
    }

    function extractAlertArray(payload) {
        if (Array.isArray(payload)) return payload;

        const keys = ['alerts', 'data', 'results', 'items', 'records'];

        if (payload && typeof payload === 'object') {
            for (const key of keys) {
                if (Array.isArray(payload[key])) return payload[key];

                if (payload[key] && typeof payload[key] === 'object') {
                    for (const nestedKey of keys) {
                        if (Array.isArray(payload[key][nestedKey])) {
                            return payload[key][nestedKey];
                        }
                    }
                }
            }
        }

        throw new Error(
            'Unexpected API response. Expected an array or an object containing an alerts array.'
        );
    }

    // ------------------------------------------------------------
    // NORMALIZE ALERT DATA
    // ------------------------------------------------------------

    function normalizeSeverity(value) {
        const severity = String(value ?? 'INFO').trim().toUpperCase();

        if (['CRITICAL', 'FATAL', 'EMERGENCY', 'SEVERE'].includes(severity)) {
            return 'CRITICAL';
        }

        if (['HIGH', 'ERROR'].includes(severity)) return 'HIGH';

        if (['MEDIUM', 'MODERATE', 'WARNING', 'WARN'].includes(severity)) {
            return 'MEDIUM';
        }

        if (['LOW', 'MINOR'].includes(severity)) return 'LOW';

        if (['INFO', 'INFORMATIONAL', 'NOTICE', 'DEBUG'].includes(severity)) {
            return 'INFO';
        }

        return 'INFO';
    }

    function normalizeStatus(value) {
        const status = String(value ?? 'OPEN').trim().toUpperCase()
            .replace(/[\s-]+/g, '_');

        if (['RESOLVED', 'FIXED', 'MITIGATED'].includes(status)) {
            return 'RESOLVED';
        }

        if (['CLOSED', 'DONE'].includes(status)) return 'CLOSED';

        if (['INVESTIGATING', 'IN_PROGRESS', 'INPROGRESS'].includes(status)) {
            return 'INVESTIGATING';
        }

        if (['CONTAINED', 'MITIGATION_IN_PROGRESS'].includes(status)) {
            return 'INVESTIGATING';
        }

        if (['FALSE_POSITIVE', 'FALSEPOSITIVE'].includes(status)) {
            return 'FALSE_POSITIVE';
        }

        return 'OPEN';
    }

    function parseTimestamp(value) {
        if (value === null || value === undefined || value === '') return null;

        if (typeof value === 'number' || /^\d+(\.\d+)?$/.test(String(value))) {
            const number = Number(value);
            if (!Number.isFinite(number)) return null;
            return number < 100000000000 ? number * 1000 : number;
        }

        const parsed = Date.parse(value);
        return Number.isNaN(parsed) ? null : parsed;
    }

    function normalizeAlert(record, index) {
        const alert = record && typeof record === 'object' ? record : {};

        const id = firstValue(alert, [
            'alert_id', 'id', 'event_id', 'log_id', 'record_id', 'uuid'
        ]);

        const agent = firstValue(alert, [
            'agent_name', 'hostname', 'host_name', 'host',
            'agent_id', 'agent', 'device_name', 'computer_name'
        ]);

        const sourceIp = firstValue(alert, [
            'source_ip', 'src_ip', 'src', 'srcip',
            'source_address', 'src_addr', 'attacker_ip',
            'remote_ip', 'client_ip', 'ip_address', 'ip'
        ]);

        const type = firstValue(alert, [
            'alert_type', 'detection_type', 'rule_name',
            'event_type', 'signature', 'title', 'rule'
        ]);

        const description = firstValue(alert, [
            'description', 'message', 'summary', 'details',
            'event_description', 'reason'
        ]);

        const timestamp = firstValue(alert, [
            'timestamp', 'detected_at', 'created_at', 'received_at',
            'event_time', 'time', 'datetime', '@timestamp'
        ]);

        const status = firstValue(alert, [
            'status', 'triage_state', 'state', 'alert_status'
        ]);

        const ruleId = firstValue(alert, [
            'rule_id', 'signature_id', 'sid', 'detection_id'
        ]);

        return {
            id: id === null ? `record-${index + 1}` : String(id),
            originalId: id === null ? null : String(id),
            type: String(type ?? 'Detection event'),
            description: String(description ?? ''),
            severity: normalizeSeverity(firstValue(alert, [
                'severity', 'level', 'priority', 'risk_level'
            ])),
            status: normalizeStatus(status),
            agent: String(agent ?? 'Unknown agent'),
            sourceIp: String(sourceIp ?? ''),
            timestamp: parseTimestamp(timestamp),
            ruleId: ruleId === null ? '' : String(ruleId),
            raw: alert
        };
    }

    function formatDate(timestamp) {
        if (!timestamp) return 'Unknown time';
        const date = new Date(timestamp);
        return Number.isNaN(date.getTime())
            ? 'Unknown time'
            : date.toLocaleString();
    }

    function formatTimeAgo(timestamp) {
        if (!timestamp) return 'Time unavailable';

        const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));

        if (seconds < 60) return 'Just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    }

    function severityClass(severity) {
        return `severity-${String(severity).toLowerCase()}`;
    }

    function statusClass(status) {
        return `status-${String(status).toLowerCase().replace(/_/g, '-')}`;
    }

    // ------------------------------------------------------------
    // LOAD AND REFRESH
    // ------------------------------------------------------------

    async function loadAlerts() {
        if (loading) return;
        loading = true;

        const refreshIcon = byId('refreshIcon');
        if (refreshIcon) refreshIcon.classList.add('fa-spin');

        if (allAlerts.length === 0) showLoading();

        try {
            const records = await fetchAlerts();

            allAlerts = records
                .map((record, index) => normalizeAlert(record, index))
                .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

            lastSuccess = Date.now();
            currentPage = 1;

            populateAgentFilter();
            applyFilters();
            updateStats();
            updateConnectionStatus(true);
            updateLastUpdate();

            console.info(`[Alerts] Loaded ${allAlerts.length} real alert records.`);
        } catch (error) {
            if (error.name === 'AbortError' && !liveEnabled) return;

            console.error('[Alerts] API error:', error);
            updateConnectionStatus(false, error.message);

            if (allAlerts.length === 0) {
                renderError(error.message);
            } else {
                setText(
                    'statusBarRight',
                    `Refresh failed; showing last successful data. ${error.message}`
                );
            }
        } finally {
            loading = false;
            if (refreshIcon) refreshIcon.classList.remove('fa-spin');
        }
    }

    function showLoading() {
        const tbody = byId('alertsBody');
        if (!tbody) return;

        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="loading-cell">
                    <i class="fas fa-circle-notch fa-spin"></i>
                    Loading alerts from the SIEM backend...
                </td>
            </tr>`;
    }

    function renderError(message) {
        const tbody = byId('alertsBody');
        if (!tbody) return;

        tbody.innerHTML = `
            <tr>
                <td colspan="8">
                    <div class="alert-empty-state">
                        <i class="fas fa-triangle-exclamation"></i>
                        <h3>Unable to load alerts</h3>
                        <p>${escapeHtml(message)}</p>
                        <p class="api-hint">API: ${escapeHtml(apiUrl('/api/alerts'))}</p>
                        <button type="button" class="filter-btn" onclick="loadAlerts()">
                            <i class="fas fa-rotate-right"></i> Retry
                        </button>
                    </div>
                </td>
            </tr>`;
    }

    function updateConnectionStatus(connected, message = '') {
        const badge = byId('liveBadge');
        const dot = byId('liveDot');
        const label = byId('liveLabel');

        if (badge) badge.classList.toggle('api-error', !connected);
        if (dot) dot.classList.toggle('offline', !connected);

        if (label) {
            label.textContent = connected
                ? (liveEnabled ? 'LIVE' : 'PAUSED')
                : 'API ERROR';
        }

        const badgeCount = byId('alertBadge');
        if (badgeCount) {
            badgeCount.textContent = allAlerts.length > 99
                ? '99+'
                : String(allAlerts.length);
        }

        const statusBar = byId('statusBarLeft');
        if (statusBar) {
            statusBar.innerHTML = connected
                ? '<i class="fas fa-circle-check"></i> Alerts API connected · Real telemetry'
                : '<i class="fas fa-triangle-exclamation"></i> Alerts API unavailable';
        }

        if (!connected && message) {
            setText('statusBarRight', message);
        }
    }

    function updateLastUpdate() {
        const now = new Date().toLocaleTimeString();
        setText('lastUpdate', `Last update: ${now}`);
        setText('statusBarRight', `Last successful scan: ${now}`);
    }

    // ------------------------------------------------------------
    // STATISTICS
    // ------------------------------------------------------------

    function updateStats() {
        setText('alertTotal', allAlerts.length);
        setText('alertCritical', allAlerts.filter(a => a.severity === 'CRITICAL').length);
        setText('alertHigh', allAlerts.filter(a => a.severity === 'HIGH').length);
        setText('alertMedium', allAlerts.filter(a => a.severity === 'MEDIUM').length);
        setText(
            'alertLow',
            allAlerts.filter(a => ['LOW', 'INFO'].includes(a.severity)).length
        );
    }

    // ------------------------------------------------------------
    // FILTERS
    // ------------------------------------------------------------

    function populateAgentFilter() {
        const select = byId('agentFilter');
        if (!select) return;

        const previousValue = select.value;

        const agents = [...new Set(
            allAlerts.map(a => a.agent).filter(
                agent => agent && agent !== 'Unknown agent'
            )
        )].sort((a, b) => a.localeCompare(b));

        select.innerHTML = '<option value="ALL">All Agents</option>';

        agents.forEach(agent => {
            const option = document.createElement('option');
            option.value = agent;
            option.textContent = agent;
            select.appendChild(option);
        });

        if ([...select.options].some(option => option.value === previousValue)) {
            select.value = previousValue;
        }
    }

    function applyFilters() {
        const query = (byId('searchInput')?.value || '').trim().toLowerCase();
        const severity = byId('severityFilter')?.value || 'ALL';
        const status = byId('statusFilter')?.value || 'ALL';
        const agent = byId('agentFilter')?.value || 'ALL';

        filteredAlerts = allAlerts.filter(alert => {
            const searchable = [
                alert.id,
                alert.type,
                alert.description,
                alert.agent,
                alert.sourceIp,
                alert.ruleId,
                alert.status,
                JSON.stringify(alert.raw)
            ].join(' ').toLowerCase();

            return (!query || searchable.includes(query)) &&
                (severity === 'ALL' || alert.severity === severity) &&
                (status === 'ALL' || alert.status === status) &&
                (agent === 'ALL' || alert.agent === agent);
        });

        currentPage = 1;
        renderAlerts();
        updatePagination();
        setText('filteredCount', `${filteredAlerts.length} alerts`);
    }

    function filterBySeverity(severity) {
        const select = byId('severityFilter');
        if (select) select.value = severity;
        applyFilters();

        document.querySelector('.table-container')
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function resetFilters() {
        if (byId('searchInput')) byId('searchInput').value = '';
        if (byId('severityFilter')) byId('severityFilter').value = 'ALL';
        if (byId('statusFilter')) byId('statusFilter').value = 'ALL';
        if (byId('agentFilter')) byId('agentFilter').value = 'ALL';

        applyFilters();
    }

    // ------------------------------------------------------------
    // RENDER ALERT TABLE — COLUMN ORDER MATCHES HTML
    // ------------------------------------------------------------

    function renderAlerts() {
        const tbody = byId('alertsBody');
        if (!tbody) return;

        if (filteredAlerts.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8">
                        <div class="alert-empty-state">
                            <i class="fas fa-shield-halved"></i>
                            <h3>${allAlerts.length ? 'No matching alerts' : 'No alerts available'}</h3>
                            <p>${
                                allAlerts.length
                                    ? 'Change your search or filters to see more results.'
                                    : 'The backend returned no alert records.'
                            }</p>
                            ${
                                allAlerts.length
                                    ? '<button class="filter-btn" onclick="resetFilters()">Clear filters</button>'
                                    : ''
                            }
                        </div>
                    </td>
                </tr>`;
            return;
        }

        const start = (currentPage - 1) * PAGE_SIZE;
        const pageAlerts = filteredAlerts.slice(start, start + PAGE_SIZE);

        tbody.innerHTML = pageAlerts.map((alert, index) => {
            const rowId = `alert-detail-${currentPage}-${index}`;
            const description = alert.description || 'No description provided by backend.';
            const sourceIp = alert.sourceIp || '—';
            const rule = alert.ruleId || '—';

            return `
                <tr class="alert-row">
                    <td class="alert-id-cell">
                        <button class="expand-btn"
                                type="button"
                                aria-label="Show alert details"
                                aria-expanded="false"
                                onclick="toggleAlertDetails('${rowId}', this)">
                            <i class="fas fa-chevron-right"></i>
                        </button>
                        <span class="mono">${escapeHtml(alert.id)}</span>
                    </td>

                    <td class="detection-cell">
                        <div class="detection-title">${escapeHtml(alert.type)}</div>
                        <div class="detection-description">${escapeHtml(description)}</div>
                        ${alert.ruleId ? `<div class="detection-rule">Rule: ${escapeHtml(rule)}</div>` : ''}
                    </td>

                    <td>
                        <span class="severity-badge ${severityClass(alert.severity)}">
                            <span class="severity-dot"></span>
                            ${escapeHtml(alert.severity)}
                        </span>
                    </td>

                    <td>
                        <div class="agent-name">
                            <i class="fas fa-laptop"></i>
                            ${escapeHtml(alert.agent)}
                        </div>
                    </td>

                    <td>
                        ${
                            alert.sourceIp
                                ? `<code class="ip-address">${escapeHtml(sourceIp)}</code>`
                                : '<span class="muted">Not provided</span>'
                        }
                    </td>

                    <td>
                        <span class="status-badge ${statusClass(alert.status)}">
                            ${escapeHtml(alert.status.replace(/_/g, ' '))}
                        </span>
                    </td>

                    <td>
                        <div class="detected-time">${escapeHtml(
                            alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'
                        )}</div>
                        <div class="time-ago">${escapeHtml(formatTimeAgo(alert.timestamp))}</div>
                    </td>
                </tr>

                <tr class="alert-detail-row" id="${rowId}" hidden>
                    <td colspan="8">
                        <div class="alert-detail-panel">
                            <div class="detail-heading">
                                <i class="fas fa-circle-info"></i>
                                Alert details
                            </div>
                            <div class="detail-grid">
                                <div class="detail-item">
                                    <span>Alert ID</span>
                                    <strong>${escapeHtml(alert.id)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Detection</span>
                                    <strong>${escapeHtml(alert.type)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Severity</span>
                                    <strong>${escapeHtml(alert.severity)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Agent / Host</span>
                                    <strong>${escapeHtml(alert.agent)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Source Address</span>
                                    <strong>${escapeHtml(sourceIp)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Rule ID</span>
                                    <strong>${escapeHtml(rule)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Triage State</span>
                                    <strong>${escapeHtml(alert.status)}</strong>
                                </div>
                                <div class="detail-item">
                                    <span>Detected At</span>
                                    <strong>${escapeHtml(formatDate(alert.timestamp))}</strong>
                                </div>
                            </div>
                            <div class="raw-heading">Raw backend record</div>
                            <pre class="raw-alert">${escapeHtml(JSON.stringify(alert.raw, null, 2))}</pre>
                        </div>
                    </td>
                </tr>`;
        }).join('');
    }

    function toggleAlertDetails(rowId, button) {
        const row = byId(rowId);
        if (!row) return;

        const opening = row.hidden;
        row.hidden = !opening;

        if (button) {
            button.setAttribute('aria-expanded', String(opening));
            button.classList.toggle('expanded', opening);
        }
    }

    // ------------------------------------------------------------
    // PAGINATION
    // ------------------------------------------------------------

    function updatePagination() {
        const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / PAGE_SIZE));
        currentPage = Math.min(currentPage, totalPages);

        setText(
            'pageInfo',
            `Showing ${filteredAlerts.length} alerts · Page ${currentPage} of ${totalPages}`
        );

        const previous = byId('prevPage');
        const next = byId('nextPage');

        if (previous) previous.disabled = currentPage <= 1;
        if (next) next.disabled = currentPage >= totalPages;
    }

    function changePage(delta) {
        const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / PAGE_SIZE));
        const nextPage = currentPage + Number(delta);

        if (nextPage < 1 || nextPage > totalPages) return;

        currentPage = nextPage;
        renderAlerts();
        updatePagination();

        document.querySelector('.table-scroll')
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ------------------------------------------------------------
    // EXPORTS
    // ------------------------------------------------------------

    function downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');

        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function exportAlertsCSV() {
        if (filteredAlerts.length === 0) {
            window.alert('There are no alerts to export.');
            return;
        }

        const headers = [
            'Alert ID', 'Detection Type', 'Description', 'Severity',
            'Agent', 'Source IP', 'Status', 'Rule ID', 'Detected At'
        ];

        const rows = filteredAlerts.map(alert => [
            alert.id,
            alert.type,
            alert.description,
            alert.severity,
            alert.agent,
            alert.sourceIp,
            alert.status,
            alert.ruleId,
            formatDate(alert.timestamp)
        ]);

        const csvCell = value =>
            `"${String(value ?? '').replace(/"/g, '""')}"`;

        const csv = [
            headers.map(csvCell).join(','),
            ...rows.map(row => row.map(csvCell).join(','))
        ].join('\r\n');

        downloadFile(
            '\uFEFF' + csv,
            `siem-alerts-${new Date().toISOString().slice(0, 10)}.csv`,
            'text/csv;charset=utf-8;'
        );
    }

    function exportAlertsJSON() {
        if (filteredAlerts.length === 0) {
            window.alert('There are no alerts to export.');
            return;
        }

        const output = filteredAlerts.map(alert => alert.raw);

        downloadFile(
            JSON.stringify(output, null, 2),
            `siem-alerts-${new Date().toISOString().slice(0, 10)}.json`,
            'application/json'
        );
    }

    // ------------------------------------------------------------
    // LIVE REFRESH
    // ------------------------------------------------------------

    function toggleLive() {
        liveEnabled = !liveEnabled;

        const badge = byId('liveBadge');
        if (badge) {
            badge.title = liveEnabled
                ? 'Click to pause auto-refresh'
                : 'Click to resume auto-refresh';
        }

        if (liveEnabled) {
            startAutoRefresh();
            loadAlerts();
        } else {
            stopAutoRefresh();
            updateConnectionStatus(Boolean(lastSuccess));
            setText('statusBarRight', 'Auto-refresh paused.');
        }
    }

    function startAutoRefresh() {
        stopAutoRefresh();

        if (liveEnabled) {
            refreshTimer = setInterval(loadAlerts, REFRESH_MS);
        }
    }

    function stopAutoRefresh() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    }

    // ------------------------------------------------------------
    // INITIALIZATION
    // ------------------------------------------------------------

    function initialize() {
        loadAlerts();
        startAutoRefresh();

        byId('alertModal')?.addEventListener('click', event => {
            if (event.target.id === 'alertModal') {
                byId('alertModal').classList.remove('show');
            }
        });
    }

    window.loadAlerts = loadAlerts;
    window.applyFilters = applyFilters;
    window.filterBySeverity = filterBySeverity;
    window.resetFilters = resetFilters;
    window.changePage = changePage;
    window.toggleLive = toggleLive;
    window.toggleAlertDetails = toggleAlertDetails;
    window.exportAlertsCSV = exportAlertsCSV;
    window.exportAlertsJSON = exportAlertsJSON;

    window.SiemAlerts = {
        load: loadAlerts,
        getAll: () => [...allAlerts],
        getFiltered: () => [...filteredAlerts],
        refresh: loadAlerts
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, { once: true });
    } else {
        initialize();
    }
})();
