// ════════════════════════════════════════════════════════════
//  MAIN — SOC CORE ENGINE & SHARED UTILITIES
//  REAL DATA ONLY
//
//  Rules:
//  - No mock telemetry
//  - No random telemetry
//  - No hardcoded agents
//  - No fake alerts
//  - No simulation fallback
//  - All SOC data must come from the backend API
// ════════════════════════════════════════════════════════════

(function () {
    'use strict';

    // ─────────────────────────────────────────────────────────
    // API CONFIGURATION
    // ─────────────────────────────────────────────────────────

    const DEFAULT_API_BASE = 'http://100.90.174.77:5000';

    let apiBase =
        localStorage.getItem('siem_api_base') ||
        DEFAULT_API_BASE;

    let soundEnabled =
        localStorage.getItem('siem_sound_enabled') === 'true';

    let apiOnline = false;
    let lastApiError = null;


    // ─────────────────────────────────────────────────────────
    // AUDIO ALERT SYSTEM
    // ─────────────────────────────────────────────────────────

    let audioCtx = null;

    function playCyberAlert(type = 'critical') {
        if (!soundEnabled) return;

        try {
            if (!audioCtx) {
                audioCtx = new (
                    window.AudioContext ||
                    window.webkitAudioContext
                )();
            }

            if (audioCtx.state === 'suspended') {
                audioCtx.resume();
            }

            const osc = audioCtx.createOscillator();
            const gain = audioCtx.createGain();

            osc.connect(gain);
            gain.connect(audioCtx.destination);

            const now = audioCtx.currentTime;

            if (type === 'critical') {
                osc.type = 'sawtooth';

                osc.frequency.setValueAtTime(
                    880,
                    now
                );

                osc.frequency.exponentialRampToValueAtTime(
                    440,
                    now + 0.15
                );

                gain.gain.setValueAtTime(
                    0.12,
                    now
                );

                gain.gain.exponentialRampToValueAtTime(
                    0.01,
                    now + 0.18
                );

                osc.start(now);
                osc.stop(now + 0.18);

            } else {
                osc.type = 'sine';

                osc.frequency.setValueAtTime(
                    587.33,
                    now
                );

                osc.frequency.exponentialRampToValueAtTime(
                    880,
                    now + 0.12
                );

                gain.gain.setValueAtTime(
                    0.08,
                    now
                );

                gain.gain.exponentialRampToValueAtTime(
                    0.01,
                    now + 0.15
                );

                osc.start(now);
                osc.stop(now + 0.15);
            }

        } catch (error) {
            console.warn(
                '[SIEM] Audio alert unavailable:',
                error
            );
        }
    }


    // ─────────────────────────────────────────────────────────
    // TOAST NOTIFICATIONS
    // ─────────────────────────────────────────────────────────

    function showToast(
        message,
        type = 'info',
        title = ''
    ) {
        let container =
            document.getElementById(
                'siemToastContainer'
            );

        if (!container) {
            container =
                document.createElement('div');

            container.id =
                'siemToastContainer';

            document.body.appendChild(
                container
            );
        }

        const toast =
            document.createElement('div');

        toast.className =
            `siem-toast ${type}`;

        const icons = {
            critical: 'fa-shield-virus',
            error: 'fa-exclamation-circle',
            warning: 'fa-triangle-exclamation',
            success: 'fa-circle-check',
            info: 'fa-bell'
        };

        const iconClass =
            icons[type] ||
            'fa-info-circle';

        toast.innerHTML = `
            <i class="fas ${iconClass}"></i>

            <div style="flex:1;">
                ${
                    title
                        ? `
                            <strong
                                style="
                                    display:block;
                                    font-size:0.8rem;
                                    margin-bottom:2px;
                                "
                            >
                                ${escapeHtml(title)}
                            </strong>
                          `
                        : ''
                }

                <span>
                    ${escapeHtml(message)}
                </span>
            </div>

            <button
                type="button"
                aria-label="Close notification"
                onclick="this.parentElement.remove()"
                style="
                    background:none;
                    border:none;
                    color:var(--text-muted);
                    cursor:pointer;
                    padding:2px;
                "
            >
                <i class="fas fa-times"></i>
            </button>
        `;

        container.appendChild(toast);

        if (
            type === 'critical' ||
            type === 'error'
        ) {
            playCyberAlert('critical');
        }

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform =
                'translateX(60px)';

            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 300);

        }, 4500);
    }


    // ─────────────────────────────────────────────────────────
    // HTML ESCAPE UTILITY
    // ─────────────────────────────────────────────────────────

    function escapeHtml(value) {
        if (
            value === null ||
            value === undefined
        ) {
            return '';
        }

        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }


    // ─────────────────────────────────────────────────────────
    // API NORMALIZATION
    // ─────────────────────────────────────────────────────────

    function normalizeApiEndpoint(endpoint) {
        if (!endpoint) {
            return '';
        }

        const value = String(endpoint);

        if (
            value.startsWith('http://') ||
            value.startsWith('https://')
        ) {
            return value;
        }

        if (value.startsWith('/')) {
            return `${apiBase}${value}`;
        }

        return `${apiBase}/${value}`;
    }


    // ─────────────────────────────────────────────────────────
    // UNIVERSAL API FETCHER
    //
    // IMPORTANT:
    // There is NO simulation fallback here.
    //
    // Backend response:
    //     return real data
    //
    // Backend failure:
    //     return null
    //
    // This prevents fake data from entering the UI.
    // ─────────────────────────────────────────────────────────

    async function fetchAPI(
        endpoint,
        options = {}
    ) {
        const url =
            normalizeApiEndpoint(endpoint);

        if (!url) {
            console.error(
                '[SIEM API] Empty endpoint'
            );

            return null;
        }

        const timeout =
            Number.isFinite(options.timeout)
                ? options.timeout
                : 8000;

        const controller =
            new AbortController();

        const timeoutId =
            setTimeout(
                () => controller.abort(),
                timeout
            );

        try {
            const requestOptions = {
                method:
                    options.method || 'GET',

                headers: {
                    Accept:
                        'application/json',

                    ...(options.headers || {})
                },

                signal:
                    controller.signal
            };

            if (
                options.body !== undefined
            ) {
                requestOptions.body =
                    typeof options.body === 'string'
                        ? options.body
                        : JSON.stringify(
                            options.body
                        );

                if (
                    !requestOptions.headers[
                        'Content-Type'
                    ]
                ) {
                    requestOptions.headers[
                        'Content-Type'
                    ] =
                        'application/json';
                }
            }

            const response =
                await fetch(
                    url,
                    requestOptions
                );

            if (!response.ok) {
                throw new Error(
                    `HTTP ${response.status} ${response.statusText}`
                );
            }

            const contentType =
                response.headers.get(
                    'content-type'
                ) || '';

            let data;

            if (
                contentType.includes(
                    'application/json'
                )
            ) {
                data =
                    await response.json();
            } else {
                const text =
                    await response.text();

                try {
                    data =
                        JSON.parse(text);
                } catch (_) {
                    data = text;
                }
            }

            apiOnline = true;
            lastApiError = null;

            updateConnectionIndicator();

            return data;

        } catch (error) {
            apiOnline = false;
            lastApiError = error;

            updateConnectionIndicator();

            console.error(
                `[SIEM API] Request failed: ${endpoint}`,
                error
            );

            return null;

        } finally {
            clearTimeout(timeoutId);
        }
    }


    // ─────────────────────────────────────────────────────────
    // API HELPERS
    // ─────────────────────────────────────────────────────────

    async function postAPI(
        endpoint,
        body = {},
        options = {}
    ) {
        return fetchAPI(
            endpoint,
            {
                ...options,
                method: 'POST',
                body
            }
        );
    }


    async function putAPI(
        endpoint,
        body = {},
        options = {}
    ) {
        return fetchAPI(
            endpoint,
            {
                ...options,
                method: 'PUT',
                body
            }
        );
    }


    async function patchAPI(
        endpoint,
        body = {},
        options = {}
    ) {
        return fetchAPI(
            endpoint,
            {
                ...options,
                method: 'PATCH',
                body
            }
        );
    }


    async function deleteAPI(
        endpoint,
        options = {}
    ) {
        return fetchAPI(
            endpoint,
            {
                ...options,
                method: 'DELETE'
            }
        );
    }


    // ─────────────────────────────────────────────────────────
    // CONNECTION INDICATOR
    // ─────────────────────────────────────────────────────────

    function updateConnectionIndicator() {
        let pill =
            document.getElementById(
                'siemConnectionPill'
            );

        const headerActions =
            document.querySelector(
                '.header-actions'
            );

        if (
            !pill &&
            headerActions
        ) {
            pill =
                document.createElement('div');

            pill.id =
                'siemConnectionPill';

            pill.className =
                'mode-pill';

            pill.onclick = () => {
                const message =
                    apiOnline
                        ? `Connected to ${apiBase}`
                        : lastApiError
                            ? `Backend unavailable: ${lastApiError.message}`
                            : `Backend status unknown`;

                showToast(
                    message,
                    apiOnline
                        ? 'success'
                        : 'warning',
                    apiOnline
                        ? 'Live API'
                        : 'API Offline'
                );
            };

            headerActions.insertBefore(
                pill,
                headerActions.firstChild
            );
        }

        if (!pill) {
            return;
        }

        if (apiOnline) {
            pill.className =
                'mode-pill connected';

            pill.innerHTML = `
                <i
                    class="fas fa-link"
                    style="color:var(--green)"
                ></i>

                <span>
                    LIVE API
                </span>
            `;

            pill.title =
                `Connected to ${apiBase}`;

        } else {
            pill.className =
                'mode-pill';

            pill.innerHTML = `
                <i
                    class="fas fa-link-slash"
                    style="color:var(--red)"
                ></i>

                <span>
                    API OFFLINE
                </span>
            `;

            pill.title =
                lastApiError
                    ? `Backend unavailable: ${lastApiError.message}`
                    : 'Backend API unavailable';
        }
    }


    // ─────────────────────────────────────────────────────────
    // API BASE URL
    // ─────────────────────────────────────────────────────────

    function setApiBase(url) {
        if (!url) {
            showToast(
                'API server URL cannot be empty.',
                'error',
                'Invalid API URL'
            );

            return false;
        }

        const normalized =
            String(url)
                .trim()
                .replace(/\/+$/, '');

        try {
            new URL(normalized);
        } catch (_) {
            showToast(
                'Please enter a valid HTTP/HTTPS API URL.',
                'error',
                'Invalid API URL'
            );

            return false;
        }

        apiBase = normalized;

        localStorage.setItem(
            'siem_api_base',
            apiBase
        );

        apiOnline = false;
        lastApiError = null;

        updateConnectionIndicator();

        showToast(
            `API Server updated to ${apiBase}`,
            'success',
            'API Configuration'
        );

        return true;
    }


    // ─────────────────────────────────────────────────────────
    // SOUND CONTROL
    // ─────────────────────────────────────────────────────────

    function toggleSound() {
        soundEnabled =
            !soundEnabled;

        localStorage.setItem(
            'siem_sound_enabled',
            String(soundEnabled)
        );

        showToast(
            `Audio alerts ${
                soundEnabled
                    ? 'Enabled'
                    : 'Disabled'
            }`,
            'info',
            'Audio Alerts'
        );

        if (soundEnabled) {
            playCyberAlert('info');
        }

        return soundEnabled;
    }


    // ─────────────────────────────────────────────────────────
    // FORMATTERS
    // ─────────────────────────────────────────────────────────

    function formatTimeAgo(timestamp) {
        if (!timestamp) {
            return '—';
        }

        const date =
            new Date(timestamp);

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return '—';
        }

        const diff =
            Math.floor(
                (
                    Date.now() -
                    date.getTime()
                ) / 1000
            );

        if (diff < 0) {
            return 'Just now';
        }

        if (diff < 15) {
            return 'Just now';
        }

        if (diff < 60) {
            return `${diff}s ago`;
        }

        if (diff < 3600) {
            return `${Math.floor(
                diff / 60
            )}m ago`;
        }

        if (diff < 86400) {
            return `${Math.floor(
                diff / 3600
            )}h ago`;
        }

        return `${Math.floor(
            diff / 86400
        )}d ago`;
    }


    function formatDate(timestamp) {
        if (!timestamp) {
            return '—';
        }

        const date =
            new Date(timestamp);

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return String(timestamp);
        }

        return date
            .toISOString()
            .substring(0, 19)
            .replace('T', ' ');
    }


    function formatNumber(value) {
        if (
            value === null ||
            value === undefined ||
            value === ''
        ) {
            return '—';
        }

        const number =
            Number(value);

        if (
            Number.isNaN(number)
        ) {
            return String(value);
        }

        return number.toLocaleString();
    }


    // ─────────────────────────────────────────────────────────
    // SEVERITY
    // ─────────────────────────────────────────────────────────

    function getSeverityColor(severity) {
        const colors = {
            CRITICAL: '#ff4757',
            HIGH: '#ff9f43',
            MEDIUM: '#facc15',
            LOW: '#00f5a0',
            INFO: '#38bdf8'
        };

        const key =
            String(
                severity || 'INFO'
            ).toUpperCase();

        return (
            colors[key] ||
            '#64748b'
        );
    }


    function getSeverityBadge(
        severity
    ) {
        if (
            severity === null ||
            severity === undefined ||
            severity === ''
        ) {
            return `
                <span class="siem-badge">
                    —
                </span>
            `;
        }

        const s =
            String(
                severity
            ).toUpperCase();

        return `
            <span
                class="siem-badge badge-${escapeHtml(
                    s
                )}"
            >
                ${escapeHtml(s)}
            </span>
        `;
    }


    // ─────────────────────────────────────────────────────────
    // STATUS
    // ─────────────────────────────────────────────────────────

    function getStatusBadge(status) {
        if (
            status === null ||
            status === undefined ||
            status === ''
        ) {
            return `
                <span class="siem-badge">
                    —
                </span>
            `;
        }

        const st =
            String(
                status
            ).toUpperCase();

        return `
            <span
                class="siem-badge badge-${escapeHtml(
                    st
                )}"
            >
                ${escapeHtml(st)}
            </span>
        `;
    }


    // ─────────────────────────────────────────────────────────
    // DEVICE ICON
    //
    // This is only presentation logic.
    // It does NOT create device data.
    // ─────────────────────────────────────────────────────────

    function getDeviceIcon(agentId) {
        if (!agentId) {
            return 'fa-server';
        }

        const id =
            String(
                agentId
            ).toLowerCase();

        if (
            id.includes('kali')
        ) {
            return 'fa-laptop-code';
        }

        if (
            id.includes('zorin') ||
            id.includes('desktop')
        ) {
            return 'fa-desktop';
        }

        if (
            id.includes('gw') ||
            id.includes('fw') ||
            id.includes('firewall')
        ) {
            return 'fa-shield-halved';
        }

        if (
            id.includes('db') ||
            id.includes('sql') ||
            id.includes('data')
        ) {
            return 'fa-database';
        }

        return 'fa-server';
    }


    // ─────────────────────────────────────────────────────────
    // LAST UPDATE
    // ─────────────────────────────────────────────────────────

    function updateLastUpdate(
        timestamp = null
    ) {
        const now =
            timestamp
                ? new Date(timestamp)
                : new Date();

        if (
            Number.isNaN(
                now.getTime()
            )
        ) {
            return;
        }

        const time =
            now.toLocaleTimeString();

        const lastEl =
            document.getElementById(
                'lastUpdate'
            );

        if (lastEl) {
            lastEl.textContent =
                time;
        }

        const scanEl =
            document.getElementById(
                'statusBarRight'
            );

        if (scanEl) {
            scanEl.textContent =
                `Last scan: ${time}`;
        }
    }


    // ─────────────────────────────────────────────────────────
    // EXPORT CSV
    // ─────────────────────────────────────────────────────────

    function exportToCSV(
        arg1,
        arg2,
        arg3
    ) {
        let filename =
            'siem_export.csv';

        let csvContent = '';

        let count = 0;

        // Signature:
        // exportToCSV(dataArray, filename)

        if (
            Array.isArray(arg1)
        ) {
            const data =
                arg1;

            filename =
                typeof arg2 === 'string'
                    ? arg2
                    : filename;

            count =
                data.length;

            if (
                data.length > 0
            ) {
                const headers =
                    Object.keys(
                        data[0]
                    );

                csvContent +=
                    headers.join(',') +
                    '\n';

                data.forEach(
                    item => {
                        csvContent +=
                            headers
                                .map(
                                    header =>
                                        `"${String(
                                            item[
                                                header
                                            ] ??
                                            ''
                                        ).replace(
                                            /"/g,
                                            '""'
                                        )}"`
                                )
                                .join(',') +
                            '\n';
                    }
                );
            }

        // Signature:
        // exportToCSV(filename, rows, headers)

        } else if (
            typeof arg1 === 'string' &&
            Array.isArray(arg2)
        ) {
            filename =
                arg1;

            const rows =
                arg2;

            const headers =
                Array.isArray(arg3)
                    ? arg3
                    : [];

            count =
                rows.length;

            if (
                headers.length > 0
            ) {
                csvContent +=
                    headers.join(',') +
                    '\n';
            }

            rows.forEach(
                row => {
                    csvContent +=
                        row
                            .map(
                                value =>
                                    `"${String(
                                        value ??
                                        ''
                                    ).replace(
                                        /"/g,
                                        '""'
                                    )}"`
                            )
                            .join(',') +
                        '\n';
                }
            );
        }

        const blob =
            new Blob(
                [csvContent],
                {
                    type:
                        'text/csv;charset=utf-8;'
                }
            );

        const url =
            URL.createObjectURL(
                blob
            );

        const a =
            document.createElement(
                'a'
            );

        a.href = url;
        a.download = filename;

        document.body.appendChild(a);
        a.click();
        a.remove();

        URL.revokeObjectURL(url);

        showToast(
            `Exported ${count} records to ${filename}`,
            'success',
            'Export Complete'
        );
    }


    // ─────────────────────────────────────────────────────────
    // COMMAND PALETTE
    // ─────────────────────────────────────────────────────────

    function initCommandPalette() {
        let palette =
            document.getElementById(
                'siemCmdPalette'
            );

        if (palette) {
            return;
        }

        palette =
            document.createElement(
                'div'
            );

        palette.id =
            'siemCmdPalette';

        palette.className =
            'modal-overlay';

        palette.innerHTML = `
            <div
                class="modal-container"
                style="
                    max-width:520px;
                    padding:20px;
                "
            >
                <div
                    style="
                        display:flex;
                        align-items:center;
                        gap:10px;
                        padding-bottom:12px;
                        border-bottom:1px solid var(--border-color);
                    "
                >
                    <i
                        class="fas fa-search"
                        style="color:var(--green)"
                    ></i>

                    <input
                        type="text"
                        id="cmdInput"
                        placeholder="Quick Jump (Dashboard, Alerts, Map, Logs, Devices)..."
                        style="
                            background:none;
                            border:none;
                            color:var(--text-primary);
                            width:100%;
                            font-size:0.95rem;
                            outline:none;
                            font-family:inherit;
                        "
                    >

                    <span
                        style="
                            font-size:0.6rem;
                            background:var(--bg-hover);
                            padding:2px 8px;
                            border-radius:4px;
                            color:var(--text-muted)
                        "
                    >
                        ESC
                    </span>
                </div>

                <div
                    id="cmdResults"
                    style="
                        margin-top:12px;
                        display:flex;
                        flex-direction:column;
                        gap:6px;
                        max-height:300px;
                        overflow-y:auto;
                    "
                >

                    <a
                        href="index.html"
                        class="action-btn"
                    >
                        <i class="fas fa-th-large text-green"></i>
                        Dashboard · Main Overview
                    </a>

                    <a
                        href="alerts.html"
                        class="action-btn"
                    >
                        <i class="fas fa-bell text-orange"></i>
                        Alerts & Detections
                    </a>

                    <a
                        href="logs.html"
                        class="action-btn"
                    >
                        <i class="fas fa-file-alt text-blue"></i>
                        Live Log Stream
                    </a>

                    <a
                        href="devices.html"
                        class="action-btn"
                    >
                        <i class="fas fa-server text-purple"></i>
                        Managed Devices & Agents
                    </a>

                    <a
                        href="incidents.html"
                        class="action-btn"
                    >
                        <i class="fas fa-shield-alt text-red"></i>
                        Incident Triage Room
                    </a>

                    <a
                        href="map.html"
                        class="action-btn"
                    >
                        <i class="fas fa-globe-americas text-green"></i>
                        Global Threat Map
                    </a>

                    <a
                        href="threat-intel.html"
                        class="action-btn"
                    >
                        <i class="fas fa-chart-line text-cyan"></i>
                        Threat Intelligence
                    </a>

                    <a
                        href="reports.html"
                        class="action-btn"
                    >
                        <i class="fas fa-file-pdf text-yellow"></i>
                        Executive Reports
                    </a>

                    <a
                        href="settings.html"
                        class="action-btn"
                    >
                        <i class="fas fa-cog text-gray"></i>
                        SIEM Node Settings
                    </a>

                    <a
                        href="users.html"
                        class="action-btn"
                    >
                        <i class="fas fa-users text-purple"></i>
                        Access Control & Analysts
                    </a>

                </div>
            </div>
        `;

        document.body.appendChild(
            palette
        );

        palette.onclick = (
            event
        ) => {
            if (
                event.target ===
                palette
            ) {
                palette.classList.remove(
                    'show'
                );
            }
        };

        window.addEventListener(
            'keydown',
            event => {
                if (
                    (
                        event.metaKey ||
                        event.ctrlKey
                    ) &&
                    event.key.toLowerCase() ===
                        'k'
                ) {
                    event.preventDefault();

                    palette.classList.toggle(
                        'show'
                    );

                    if (
                        palette.classList.contains(
                            'show'
                        )
                    ) {
                        setTimeout(
                            () => {
                                document
                                    .getElementById(
                                        'cmdInput'
                                    )
                                    ?.focus();
                            },
                            50
                        );
                    }
                }

                if (
                    event.key ===
                    'Escape' &&
                    palette.classList.contains(
                        'show'
                    )
                ) {
                    palette.classList.remove(
                        'show'
                    );
                }
            }
        );

        const input =
            document.getElementById(
                'cmdInput'
            );

        if (input) {
            input.oninput = () => {
                const query =
                    input.value
                        .toLowerCase()
                        .trim();

                const links =
                    palette.querySelectorAll(
                        '#cmdResults a'
                    );

                links.forEach(
                    link => {
                        const text =
                            link.textContent
                                .toLowerCase();

                        link.style.display =
                            text.includes(query)
                                ? 'inline-flex'
                                : 'none';
                    }
                );
            };
        }
    }


    // ─────────────────────────────────────────────────────────
    // MOBILE NAVIGATION
    // ─────────────────────────────────────────────────────────

    function initMobileNav() {
        const header =
            document.querySelector(
                '.main-header'
            );

        const sidebar =
            document.querySelector(
                '.sidebar'
            );

        if (
            !header ||
            !sidebar
        ) {
            return;
        }

        let toggleBtn =
            document.getElementById(
                'mobileNavToggle'
            );

        if (!toggleBtn) {
            toggleBtn =
                document.createElement(
                    'button'
                );

            toggleBtn.id =
                'mobileNavToggle';

            toggleBtn.className =
                'mobile-nav-toggle';

            toggleBtn.innerHTML =
                '<i class="fas fa-bars"></i>';

            toggleBtn.setAttribute(
                'aria-label',
                'Toggle navigation'
            );

            toggleBtn.onclick = () => {
                sidebar.classList.toggle(
                    'open'
                );
            };

            header.insertBefore(
                toggleBtn,
                header.firstChild
            );
        }
    }


    // ─────────────────────────────────────────────────────────
    // INITIAL API HEALTH CHECK
    // ─────────────────────────────────────────────────────────

    async function checkApiHealth() {
        const candidates = [
            '/api/health',
            '/api/stats'
        ];

        for (
            const endpoint of candidates
        ) {
            const result =
                await fetchAPI(
                    endpoint,
                    {
                        timeout: 5000
                    }
                );

            if (
                result !== null
            ) {
                apiOnline = true;
                updateConnectionIndicator();
                return true;
            }
        }

        apiOnline = false;
        updateConnectionIndicator();

        return false;
    }


    // ─────────────────────────────────────────────────────────
    // GLOBAL SIEM ENGINE
    // ─────────────────────────────────────────────────────────

    window.SiemEngine = {

        // API
        get apiBase() {
            return apiBase;
        },

        get isSimulated() {
            // Kept for compatibility with existing
            // pages during migration.
            //
            // IMPORTANT:
            // There is NO simulation mode anymore.
            return false;
        },

        get isLive() {
            return apiOnline;
        },

        get lastApiError() {
            return lastApiError;
        },

        setApiBase,

        fetchAPI,
        postAPI,
        putAPI,
        patchAPI,
        deleteAPI,

        checkApiHealth,

        // Audio
        toggleSound,

        get soundEnabled() {
            return soundEnabled;
        },

        playAlert:
            playCyberAlert,

        // Notifications
        showToast,

        // Formatters
        formatTimeAgo,
        formatDate,
        formatNumber,

        // Presentation helpers
        getSeverityColor,
        getSeverityBadge,
        getStatusBadge,
        getDeviceIcon,

        // Utilities
        updateLastUpdate,
        exportToCSV,

        escapeHtml
    };


    // ─────────────────────────────────────────────────────────
    // AUTO INITIALIZATION
    // ─────────────────────────────────────────────────────────

    document.addEventListener(
        'DOMContentLoaded',
        () => {

            initCommandPalette();

            initMobileNav();

            updateConnectionIndicator();

            // Do not block the page while checking API.
            // This only determines connection status.
            checkApiHealth();
        }
    );

})();