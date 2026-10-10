
'use strict';

/*
============================================================
MY SIEM — MANAGED ENDPOINTS
REAL BACKEND TELEMETRY ONLY
============================================================
API: GET /api/agents

No mock agents, fake IPs, fake heartbeats, or random status.
============================================================
*/

(() => {
    const API_BASE = String(
        window.SIEM_API_BASE || ''
    ).replace(/\/+$/, '');

    const PAGE_SIZE = 10;
    const REFRESH_INTERVAL = 15000;

    let allDevices = [];
    let filteredDevices = [];
    let currentPage = 1;
    let isLoading = false;
    let refreshTimer = null;
    let hasLoadedSuccessfully = false;

    const STATUS_LABELS = {
        online: 'ONLINE',
        warning: 'WARNING',
        offline: 'OFFLINE',
        unknown: 'UNKNOWN'
    };

    // --------------------------------------------------------
    // API HELPERS
    // --------------------------------------------------------

    function apiUrl(endpoint) {
        const path = endpoint.startsWith('/')
            ? endpoint
            : `/${endpoint}`;

        if (API_BASE) {
            return `${API_BASE}${path}`;
        }

        if (window.location.origin &&
            window.location.origin !== 'null') {
            return `${window.location.origin}${path}`;
        }

        throw new Error(
            'API base is missing. Configure window.SIEM_API_BASE in devices.html.'
        );
    }

    async function fetchAPI(endpoint) {
        const controller = new AbortController();
        const timeout = setTimeout(
            () => controller.abort(),
            10000
        );

        try {
            const response = await fetch(apiUrl(endpoint), {
                method: 'GET',
                headers: {
                    Accept: 'application/json'
                },
                cache: 'no-store',
                signal: controller.signal
            });

            if (!response.ok) {
                throw new Error(
                    `API returned HTTP ${response.status} ${response.statusText}`
                );
            }

            const contentType =
                response.headers.get('content-type') || '';

            if (!contentType.includes('application/json')) {
                throw new Error(
                    'The API did not return JSON. Check the backend route.'
                );
            }

            return await response.json();
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error(
                    'The SIEM API request timed out after 10 seconds.'
                );
            }

            throw error;
        } finally {
            clearTimeout(timeout);
        }
    }

    /*
     * Supports common API response formats:
     * [...]
     * { "agents": [...] }
     * { "data": [...] }
     * { "results": [...] }
     * { "items": [...] }
     *
     * Does not create fallback or sample records.
     */
    function extractAgents(payload) {
        if (Array.isArray(payload)) {
            return payload;
        }

        if (!payload || typeof payload !== 'object') {
            throw new Error(
                'Invalid /api/agents response. Expected an array or JSON object containing agents.'
            );
        }

        const possibleKeys = [
            'agents',
            'data',
            'results',
            'items'
        ];

        for (const key of possibleKeys) {
            if (Array.isArray(payload[key])) {
                return payload[key];
            }

            if (
                payload[key] &&
                typeof payload[key] === 'object'
            ) {
                for (const nestedKey of possibleKeys) {
                    if (Array.isArray(payload[key][nestedKey])) {
                        return payload[key][nestedKey];
                    }
                }
            }
        }

        throw new Error(
            'Could not find an agents array in the API response. Expected an array or { agents: [...] }.'
        );
    }

    // --------------------------------------------------------
    // SAFE DISPLAY HELPERS
    // --------------------------------------------------------

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function displayValue(value) {
        if (
            value === null ||
            value === undefined ||
            String(value).trim() === ''
        ) {
            return '—';
        }

        return String(value);
    }

    function setText(id, value) {
        const element = document.getElementById(id);

        if (element) {
            element.textContent = String(value);
        }
    }

    function firstValue(object, keys) {
        for (const key of keys) {
            const value = object?.[key];

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

    // --------------------------------------------------------
    // NORMALIZE REAL AGENT RECORDS
    // --------------------------------------------------------

    function normalizeStatus(value) {
        const status = String(value ?? '')
            .trim()
            .toLowerCase();

        if ([
            'online',
            'connected',
            'active',
            'healthy',
            'up'
        ].includes(status)) {
            return 'online';
        }

        if ([
            'warning',
            'degraded',
            'lagging',
            'delayed'
        ].includes(status)) {
            return 'warning';
        }

        if ([
            'offline',
            'disconnected',
            'inactive',
            'down'
        ].includes(status)) {
            return 'offline';
        }

        return 'unknown';
    }

    function normalizeTimestamp(value) {
        if (
            value === null ||
            value === undefined ||
            value === ''
        ) {
            return null;
        }

        // Convert Unix timestamps in seconds to milliseconds.
        if (
            typeof value === 'number' ||
            /^\d+(\.\d+)?$/.test(String(value).trim())
        ) {
            const number = Number(value);

            if (!Number.isFinite(number)) {
                return null;
            }

            return number < 100000000000
                ? number * 1000
                : number;
        }

        const parsed = Date.parse(value);
        return Number.isNaN(parsed) ? null : parsed;
    }

    function normalizeDevice(agent) {
        if (!agent || typeof agent !== 'object') {
            return null;
        }

        const id = firstValue(agent, [
            'agent_id',
            'id',
            'agentId',
            'uuid'
        ]);

        const hostname = firstValue(agent, [
            'hostname',
            'host_name',
            'host',
            'computer_name',
            'computerName'
        ]);

        const name = firstValue(agent, [
            'name',
            'agent_name',
            'display_name',
            'displayName'
        ]) || hostname || id;

        const ip = firstValue(agent, [
            'ip_address',
            'ip',
            'ipAddress',
            'source_ip',
            'address'
        ]);

        const os = firstValue(agent, [
            'os',
            'operating_system',
            'operatingSystem',
            'platform',
            'os_name'
        ]);

        const version = firstValue(agent, [
            'version',
            'agent_version',
            'agentVersion',
            'version_number'
        ]);

        const statusValue = firstValue(agent, [
            'status',
            'agent_status',
            'connection_status',
            'state'
        ]);

        const lastSeen = firstValue(agent, [
            'last_seen',
            'lastSeen',
            'last_heartbeat',
            'lastHeartbeat',
            'last_heartbeat_at',
            'last_seen_at',
            'heartbeat_at',
            'updated_at',
            'timestamp'
        ]);

        return {
            id: id === null ? null : String(id),
            name: name === null ? null : String(name),
            hostname: hostname === null ? null : String(hostname),
            ip: ip === null ? null : String(ip),
            os: os === null ? null : String(os),
            version: version === null ? null : String(version),
            status: normalizeStatus(statusValue),
            last_seen: normalizeTimestamp(lastSeen),
            raw: agent
        };
    }

    function getDeviceIcon(device) {
        const os = String(device.os || '').toLowerCase();
        const id = String(device.id || '').toLowerCase();
        const name = String(device.name || '').toLowerCase();

        if (os.includes('windows')) {
            return 'fa-brands fa-windows';
        }

        if (os.includes('mac') || os.includes('darwin')) {
            return 'fa-brands fa-apple';
        }

        if (os.includes('linux') || os.includes('ubuntu') ||
            os.includes('debian') || os.includes('kali')) {
            return 'fa-brands fa-linux';
        }

        if ((id + ' ' + name).includes('firewall')) {
            return 'fa-solid fa-shield-halved';
        }

        if ((id + ' ' + name).includes('database')) {
            return 'fa-solid fa-database';
        }

        return 'fa-solid fa-server';
    }

    function formatDate(timestamp) {
        if (!timestamp) return '—';

        const date = new Date(timestamp);

        if (Number.isNaN(date.getTime())) {
            return '—';
        }

        return date.toLocaleString();
    }

    function formatTimeAgo(timestamp) {
        if (!timestamp) return '—';

        const difference = Date.now() - timestamp;

        if (!Number.isFinite(difference)) return '—';
        if (difference < 60000) return 'Just now';

        if (difference < 3600000) {
            return `${Math.floor(difference / 60000)}m ago`;
        }

        if (difference < 86400000) {
            return `${Math.floor(difference / 3600000)}h ago`;
        }

        return `${Math.floor(difference / 86400000)}d ago`;
    }

    // --------------------------------------------------------
    // LOAD ENDPOINT TELEMETRY
    // --------------------------------------------------------

    async function loadDevices() {
        if (isLoading) return;

        isLoading = true;

        const refreshIcon = document.getElementById('refreshIcon');
        if (refreshIcon) refreshIcon.classList.add('fa-spin');

        showLoadingState();

        try {
            const payload = await fetchAPI('/api/agents');
            const agents = extractAgents(payload);

            const normalized = agents
                .map(normalizeDevice)
                .filter(Boolean);

            allDevices = normalized;
            filteredDevices = [...allDevices];
            currentPage = 1;
            hasLoadedSuccessfully = true;

            populateOSFilter();
            updateDeviceStats();
            renderDeviceCards();
            renderDevicesTable();
            updatePagination();
            updateSystemStatus(true);
            updateLastUpdate();

            console.info(
                `[Devices] Loaded ${allDevices.length} real agent record(s).`
            );
        } catch (error) {
            console.error('[Devices] Failed to load agents:', error);

            if (!hasLoadedSuccessfully) {
                allDevices = [];
                filteredDevices = [];
            }

            updateDeviceStats();
            renderDeviceCards();
            renderDevicesTable();
            updatePagination();
            updateSystemStatus(false);
            showApiError(error);
        } finally {
            isLoading = false;

            if (refreshIcon) {
                refreshIcon.classList.remove('fa-spin');
            }
        }
    }

    function showLoadingState() {
        const tbody = document.getElementById('devicesBody');

        if (tbody && allDevices.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="loading-text">
                        <i class="fas fa-spinner fa-spin"></i>
                        Loading endpoint telemetry...
                    </td>
                </tr>`;
        }

        setText('statusBarRight', 'Checking SIEM API...');
    }

    function showApiError(error) {
        const message = error?.message || 'Unknown API error';

        const tbody = document.getElementById('devicesBody');

        if (tbody && allDevices.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7">
                        <div class="empty-state" style="padding:36px 20px;text-align:center">
                            <i class="fas fa-triangle-exclamation"
                               style="color:var(--red);font-size:1.8rem"></i>
                            <h3>Endpoint telemetry unavailable</h3>
                            <p style="color:var(--text-muted);font-size:.8rem">
                                ${escapeHtml(message)}
                            </p>
                            <p style="color:var(--text-muted);font-size:.75rem">
                                API: <code>${escapeHtml(apiUrl('/api/agents'))}</code>
                            </p>
                            <button class="filter-btn" onclick="loadDevices()">
                                <i class="fas fa-sync-alt"></i> Retry
                            </button>
                        </div>
                    </td>
                </tr>`;
        }

        setText('statusBarLeft', 'System: Telemetry unavailable');
        setText('statusBarRight', message);
    }

    function updateSystemStatus(online) {
        const status = document.getElementById('statusBarLeft');

        if (!status) return;

        if (online) {
            status.innerHTML = `
                <i class="fas fa-check-circle" style="color:var(--green)"></i>
                Agent API: Connected`;
        } else {
            status.innerHTML = `
                <i class="fas fa-circle-exclamation" style="color:var(--red)"></i>
                Agent API: Unavailable`;
        }
    }

    function updateLastUpdate() {
        setText(
            'lastUpdate',
            `Updated: ${new Date().toLocaleTimeString()}`
        );

        setText(
            'statusBarRight',
            `Last successful API update: ${new Date().toLocaleTimeString()}`
        );
    }

    // --------------------------------------------------------
    // STATISTICS
    // --------------------------------------------------------

    function updateDeviceStats() {
        const total = allDevices.length;
        const online = allDevices.filter(d => d.status === 'online').length;
        const warning = allDevices.filter(d => d.status === 'warning').length;
        const offline = allDevices.filter(d => d.status === 'offline').length;
        const unknown = allDevices.filter(d => d.status === 'unknown').length;

        setText('deviceTotal', total);
        setText('deviceOnline', online);
        setText('deviceWarning', warning);
        setText('deviceOffline', offline);
        setText('deviceUnknown', unknown);
        setText('deviceCardCount', `${filteredDevices.length} devices`);
        setText('totalResults', `${filteredDevices.length} devices`);
    }

    // --------------------------------------------------------
    // OPERATING SYSTEM FILTER
    // --------------------------------------------------------

    function populateOSFilter() {
        const select = document.getElementById('osFilter');
        if (!select) return;

        const current = select.value;

        const operatingSystems = [
            ...new Set(
                allDevices
                    .map(device => device.os)
                    .filter(Boolean)
            )
        ].sort((a, b) => a.localeCompare(b));

        select.innerHTML = '<option value="ALL">All OS</option>';

        operatingSystems.forEach(os => {
            const option = document.createElement('option');
            option.value = os;
            option.textContent = os;
            select.appendChild(option);
        });

        if ([...select.options].some(option => option.value === current)) {
            select.value = current;
        }
    }

    // --------------------------------------------------------
    // HOST CARDS
    // --------------------------------------------------------

    function renderDeviceCards() {
        // HTML uses deviceCardsGrid; support older deviceCards markup too.
        const container =
            document.getElementById('deviceCardsGrid') ||
            document.getElementById('deviceCards');

        if (!container) return;

        if (filteredDevices.length === 0) {
            container.innerHTML = `
                <div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--text-muted)">
                    <i class="fas fa-server" style="font-size:1.8rem;opacity:.5"></i>
                    <h3>No endpoints to display</h3>
                    <p>${
                        allDevices.length === 0
                            ? 'The API returned no agent records.'
                            : 'No endpoints match the current filters.'
                    }</p>
                </div>`;
            return;
        }

        container.innerHTML = filteredDevices
            .slice(0, 6)
            .map(device => {
                const id = escapeHtml(device.id);
                const status = device.status;
                const icon = getDeviceIcon(device);

                return `
                    <article class="device-card"
                             role="button"
                             tabindex="0"
                             onclick="viewDevice('${id}')"
                             onkeydown="if(event.key==='Enter')viewDevice('${id}')">
                        <div class="device-header">
                            <span class="device-name">
                                <i class="${escapeHtml(icon)}"></i>
                                ${escapeHtml(displayValue(device.name))}
                            </span>
                            <span class="device-status ${status}">
                                ${STATUS_LABELS[status]}
                            </span>
                        </div>
                        <div class="device-details">
                            <span>
                                <i class="fas fa-network-wired"></i>
                                ${escapeHtml(displayValue(device.ip))}
                            </span>
                            <span>
                                <i class="fas fa-microchip"></i>
                                ${escapeHtml(displayValue(device.os))}
                            </span>
                            <span>
                                <i class="fas fa-clock"></i>
                                Last seen: ${escapeHtml(formatTimeAgo(device.last_seen))}
                            </span>
                        </div>
                        <div class="device-actions">
                            <button type="button"
                                    class="filter-btn"
                                    onclick="event.stopPropagation();viewDevice('${id}')">
                                <i class="fas fa-eye"></i> Details
                            </button>
                        </div>
                    </article>`;
            })
            .join('');
    }

    // --------------------------------------------------------
    // ENDPOINT TABLE
    // --------------------------------------------------------

    function renderDevicesTable() {
        const tbody = document.getElementById('devicesBody');
        if (!tbody) return;

        const start = (currentPage - 1) * PAGE_SIZE;
        const pageData = filteredDevices.slice(start, start + PAGE_SIZE);

        if (pageData.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7">
                        <div class="empty-state" style="padding:30px;text-align:center">
                            <i class="fas fa-server"></i>
                            <h3>No endpoints found</h3>
                            <p>${
                                allDevices.length === 0
                                    ? 'No agents were returned by the SIEM backend.'
                                    : 'Try changing your search or filters.'
                            }</p>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = pageData.map(device => {
            const id = escapeHtml(device.id);
            const status = device.status;

            return `
                <tr>
                    <td>
                        <div style="display:flex;align-items:center;gap:9px">
                            <div style="width:30px;height:30px;border-radius:6px;background:var(--bg-hover);display:flex;align-items:center;justify-content:center">
                                <i class="${escapeHtml(getDeviceIcon(device))}"
                                   style="color:var(--blue)"></i>
                            </div>
                            <div>
                                <strong>${escapeHtml(displayValue(device.name))}</strong>
                                ${
                                    device.hostname
                                        ? `<div style="font-size:.7rem;color:var(--text-muted)">${escapeHtml(device.hostname)}</div>`
                                        : ''
                                }
                                ${
                                    device.id
                                        ? `<div style="font-size:.65rem;color:var(--text-muted)">ID: ${escapeHtml(device.id)}</div>`
                                        : ''
                                }
                            </div>
                        </div>
                    </td>
                    <td><code>${escapeHtml(displayValue(device.ip))}</code></td>
                    <td>${escapeHtml(displayValue(device.os))}</td>
                    <td>
                        <span class="device-status ${status}">
                            ${STATUS_LABELS[status]}
                        </span>
                    </td>
                    <td title="${escapeHtml(formatDate(device.last_seen))}">
                        ${escapeHtml(formatTimeAgo(device.last_seen))}
                    </td>
                    <td><code>${escapeHtml(displayValue(device.version))}</code></td>
                    <td>
                        <button type="button" class="filter-btn"
                                onclick="viewDevice('${id}')">
                            <i class="fas fa-eye"></i> View
                        </button>
                    </td>
                </tr>`;
        }).join('');
    }

    // --------------------------------------------------------
    // SEARCH AND FILTERS
    // --------------------------------------------------------

    function searchDevices() {
        const searchTerm = (
            document.getElementById('searchInput')?.value || ''
        ).trim().toLowerCase();

        const statusFilter =
            document.getElementById('statusFilter')?.value || 'ALL';

        const osFilter =
            document.getElementById('osFilter')?.value || 'ALL';

        filteredDevices = allDevices.filter(device => {
            const searchable = [
                device.id,
                device.name,
                device.hostname,
                device.ip,
                device.os,
                device.version
            ].filter(Boolean).join(' ').toLowerCase();

            const matchesSearch =
                !searchTerm || searchable.includes(searchTerm);

            const matchesStatus =
                statusFilter === 'ALL' ||
                device.status === statusFilter;

            const matchesOS =
                osFilter === 'ALL' ||
                device.os === osFilter;

            return matchesSearch && matchesStatus && matchesOS;
        });

        currentPage = 1;
        updateDeviceStats();
        renderDeviceCards();
        renderDevicesTable();
        updatePagination();
    }

    function filterByStatus(status) {
        const select = document.getElementById('statusFilter');

        if (select) {
            select.value = status;
        }

        searchDevices();

        document.querySelector('.table-container')
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function resetFilters() {
        const searchInput = document.getElementById('searchInput');
        const statusFilter = document.getElementById('statusFilter');
        const osFilter = document.getElementById('osFilter');

        if (searchInput) searchInput.value = '';
        if (statusFilter) statusFilter.value = 'ALL';
        if (osFilter) osFilter.value = 'ALL';

        filteredDevices = [...allDevices];
        currentPage = 1;

        updateDeviceStats();
        renderDeviceCards();
        renderDevicesTable();
        updatePagination();
    }

    // --------------------------------------------------------
    // PAGINATION
    // --------------------------------------------------------

    function updatePagination() {
        const totalPages = Math.max(
            1,
            Math.ceil(filteredDevices.length / PAGE_SIZE)
        );

        currentPage = Math.min(currentPage, totalPages);

        setText(
            'pageInfo',
            `Showing ${filteredDevices.length} devices · Page ${currentPage} of ${totalPages}`
        );

        const previous = document.getElementById('prevPage');
        const next = document.getElementById('nextPage');

        if (previous) previous.disabled = currentPage <= 1;
        if (next) next.disabled = currentPage >= totalPages;

        setText('totalResults', `${filteredDevices.length} devices`);
    }

    function changePage(delta) {
        const totalPages = Math.max(
            1,
            Math.ceil(filteredDevices.length / PAGE_SIZE)
        );

        const nextPage = currentPage + Number(delta);

        if (nextPage < 1 || nextPage > totalPages) return;

        currentPage = nextPage;
        renderDevicesTable();
        updatePagination();

        document.querySelector('.table-scroll')
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // --------------------------------------------------------
    // DEVICE DETAILS
    // --------------------------------------------------------

    function findDevice(deviceId) {
        return allDevices.find(
            device => String(device.id) === String(deviceId)
        ) || null;
    }

    function detailCard(label, value) {
        return `
            <div style="background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:12px">
                <div style="font-size:.65rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:5px">
                    ${escapeHtml(label)}
                </div>
                <div style="font-size:.85rem;color:var(--text-primary);font-weight:600;overflow-wrap:anywhere">
                    ${value}
                </div>
            </div>`;
    }

    function viewDevice(deviceId) {
        const device = findDevice(deviceId);
        if (!device) return;

        const modal = document.getElementById('deviceModal');
        const content = document.getElementById('modalContent');

        if (!modal || !content) {
            console.error('[Devices] deviceModal or modalContent is missing.');
            return;
        }

        const status = device.status;

        content.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:20px">
                <div style="display:flex;align-items:center;gap:12px">
                    <i class="${escapeHtml(getDeviceIcon(device))}"
                       style="font-size:1.8rem;color:var(--blue)"></i>
                    <div>
                        <h2 style="margin:0">${escapeHtml(displayValue(device.name))}</h2>
                        <div style="font-size:.8rem;color:var(--text-muted)">
                            ${escapeHtml(displayValue(device.hostname))}
                        </div>
                    </div>
                </div>
                <button type="button" class="modal-close-btn"
                        onclick="closeDeviceModal()" aria-label="Close">
                    <i class="fas fa-times"></i>
                </button>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px">
                ${detailCard('Status',
                    `<span class="device-status ${status}">${STATUS_LABELS[status]}</span>`)}
                ${detailCard('Agent ID', escapeHtml(displayValue(device.id)))}
                ${detailCard('Hostname', escapeHtml(displayValue(device.hostname)))}
                ${detailCard('IP Address', escapeHtml(displayValue(device.ip)))}
                ${detailCard('Operating System', escapeHtml(displayValue(device.os)))}
                ${detailCard('Agent Version', escapeHtml(displayValue(device.version)))}
                ${detailCard('Last Heartbeat', escapeHtml(formatDate(device.last_seen)))}
            </div>

            <div style="margin-top:18px;border-top:1px solid var(--border-color);padding-top:14px">
                <div style="font-size:.7rem;color:var(--text-muted);margin-bottom:8px">
                    RAW BACKEND TELEMETRY
                </div>
                <pre style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:280px;overflow:auto;background:var(--bg-secondary);padding:12px;border-radius:8px;font-size:.75rem">${escapeHtml(JSON.stringify(device.raw, null, 2))}</pre>
            </div>

            <div style="display:flex;justify-content:flex-end;margin-top:16px">
                <button type="button" class="filter-btn"
                        onclick="closeDeviceModal()">Close</button>
            </div>`;

        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }

    function closeDeviceModal() {
        document.getElementById('deviceModal')?.classList.remove('show');
        document.body.style.overflow = '';
    }

    function inspectDevice(deviceId) {
        viewDevice(deviceId);
    }

    /*
     * There is no confirmed backend ping endpoint in the supplied
     * frontend/API contract. Do not fake ping results.
     */
    function pingDevice(deviceId) {
        const device = findDevice(deviceId);
        if (!device) return;

        setText(
            'statusBarRight',
            `Ping is unavailable: no configured backend ping endpoint for ${displayValue(device.name)}.`
        );
    }

    // --------------------------------------------------------
    // INITIALIZATION AND REFRESH
    // --------------------------------------------------------

    function initialize() {
        document.getElementById('deviceModal')?.addEventListener(
            'click',
            event => {
                if (event.target.id === 'deviceModal') {
                    closeDeviceModal();
                }
            }
        );

        document.addEventListener('keydown', event => {
            if (event.key === 'Escape') closeDeviceModal();
        });

        loadDevices();

        if (refreshTimer) clearInterval(refreshTimer);

        refreshTimer = setInterval(
            loadDevices,
            REFRESH_INTERVAL
        );
    }

    // --------------------------------------------------------
    // PUBLIC FUNCTIONS FOR HTML BUTTONS
    // --------------------------------------------------------

    window.SiemDevices = {
        load: loadDevices,
        refresh: loadDevices,
        search: searchDevices,
        reset: resetFilters,
        view: viewDevice,
        close: closeDeviceModal,
        getAll: () => [...allDevices],
        getFiltered: () => [...filteredDevices]
    };

    window.loadDevices = loadDevices;
    window.searchDevices = searchDevices;
    window.resetFilters = resetFilters;
    window.filterByStatus = filterByStatus;
    window.changePage = changePage;
    window.viewDevice = viewDevice;
    window.closeDeviceModal = closeDeviceModal;
    window.inspectDevice = inspectDevice;
    window.pingDevice = pingDevice;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, {
            once: true
        });
    } else {
        initialize();
    }
})();
