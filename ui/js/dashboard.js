
 // ════════════════════════════════════════════════════════════
 // MY SIEM — DASHBOARD CONTROLLER
 // REAL TELEMETRY ONLY
 //
 // DATA SOURCES
 // /api/stats
 // /api/alerts
 // /api/logs
 // /api/agents
 // /api/threat-map
 //
 // No mock data, fake agents, fake IPs, or random telemetry.
 // Map uses Leaflet with OpenStreetMap raster tiles.
 // ════════════════════════════════════════════════════════════

'use strict';

// ============================================================
// GLOBAL STATE
// ============================================================

let realDevices = [];
let realAlerts = [];
let realLogs = [];
let realStats = null;

let realThreatMap = {
    server: null,
    agents: [],
    threats: [],
    timestamp: null
};

let activities = [];

let mapInstance = null;
let mapLoaded = false;

let liveInterval = null;
let isLive = true;
let isLoading = false;

let lastAlertIds = new Set();

let dashboardMapMarkers = [];
let dashboardMapLines = [];

// ============================================================
// SAFE VALUE HELPERS
// ============================================================

function safeNumber(value, fallback = null) {
    if (value === null || value === undefined || value === '') {
        return fallback;
    }

    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function safeText(value, fallback = '—') {
    if (value === null || value === undefined || value === '') {
        return fallback;
    }

    return String(value);
}

function hasCoordinates(item) {
    if (!item) return false;

    const lat = safeNumber(item.lat ?? item.latitude);
    const lon = safeNumber(item.lon ?? item.lng ?? item.longitude);

    return (
        lat !== null &&
        lon !== null &&
        lat >= -90 &&
        lat <= 90 &&
        lon >= -180 &&
        lon <= 180
    );
}

function getLatitude(item) {
    return safeNumber(item?.lat ?? item?.latitude);
}

function getLongitude(item) {
    return safeNumber(item?.lon ?? item?.lng ?? item?.longitude);
}

// ============================================================
// NORMALIZE BACKEND RESPONSE
// ============================================================

function normalizeArrayResponse(data) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.data)) return data.data;
    if (data && Array.isArray(data.results)) return data.results;
    return [];
}

function normalizeThreatMap(data) {
    if (!data || typeof data !== 'object') {
        return {
            server: null,
            agents: [],
            threats: [],
            timestamp: null
        };
    }

    return {
        server: data.server || null,
        agents: Array.isArray(data.agents) ? data.agents : [],
        threats: Array.isArray(data.threats) ? data.threats : [],
        timestamp: data.timestamp || null
    };
}

// ============================================================
// FETCH DASHBOARD TELEMETRY
// ============================================================

async function fetchDashboardData() {
    if (isLoading) return false;

    isLoading = true;

    try {
        const stats = await SiemEngine.fetchAPI('/api/stats');

        realStats = (
            stats &&
            typeof stats === 'object' &&
            !stats.error
        ) ? stats : null;

        const alerts = await SiemEngine.fetchAPI('/api/alerts');

        realAlerts = Array.isArray(alerts)
            ? alerts
            : normalizeArrayResponse(alerts);

        const logs = await SiemEngine.fetchAPI('/api/logs');

        realLogs = Array.isArray(logs)
            ? logs
            : normalizeArrayResponse(logs);

        const agents = await SiemEngine.fetchAPI('/api/agents');

        realDevices = normalizeArrayResponse(agents).map(normalizeAgent);

        const threatMap = await SiemEngine.fetchAPI('/api/threat-map');

        realThreatMap = normalizeThreatMap(threatMap);

        updateAlertBadge();
        buildActivities();
        detectNewAlerts();

        return true;
    } catch (error) {
        console.error('[Dashboard] Telemetry loading failed:', error);

        realStats = null;
        realAlerts = [];
        realLogs = [];
        realDevices = [];

        realThreatMap = {
            server: null,
            agents: [],
            threats: [],
            timestamp: null
        };

        activities = [];

        return false;
    } finally {
        isLoading = false;
    }
}

// ============================================================
// NORMALIZE AGENT
// ============================================================

function normalizeAgent(agent) {
    if (!agent || typeof agent !== 'object') return {};

    return {
        id: agent.agent_id ?? agent.id ?? null,
        name:
            agent.hostname ??
            agent.agent_id ??
            agent.id ??
            'Unknown Agent',
        hostname: agent.hostname ?? null,
        ip: agent.ip_address ?? agent.ip ?? null,
        status: agent.status ?? null,
        os: agent.os ?? null,
        version: agent.version ?? null,
        last_seen: agent.last_seen ?? null,
        lat: safeNumber(agent.lat ?? agent.latitude),
        lon: safeNumber(agent.lon ?? agent.lng ?? agent.longitude),
        city: agent.city ?? null,
        state: agent.state ?? null,
        country: agent.country ?? null,
        icon: SiemEngine.getDeviceIcon(agent.agent_id ?? agent.id)
    };
}

// ============================================================
// ALERT BADGE
// ============================================================

function updateAlertBadge() {
    const badge = document.getElementById('alertBadge');
    if (!badge) return;

    const count = realAlerts.length;

    badge.textContent = count > 99 ? '99+' : String(count);
    badge.style.display = count > 0 ? '' : 'none';
}

// ============================================================
// NEW ALERT DETECTION
// ============================================================

function detectNewAlerts() {
    const currentIds = new Set();

    realAlerts.forEach(alert => {
        if (alert && alert.id !== undefined && alert.id !== null) {
            currentIds.add(String(alert.id));
        }
    });

    if (lastAlertIds.size > 0) {
        realAlerts.slice(0, 10).forEach(alert => {
            if (!alert || alert.id === undefined || alert.id === null) {
                return;
            }

            const id = String(alert.id);

            if (!lastAlertIds.has(id)) {
                const severity = String(alert.severity || '').toUpperCase();

                if (severity === 'CRITICAL') {
                    SiemEngine.playAlert('critical');
                }
            }
        });
    }

    lastAlertIds = currentIds;
}

// ============================================================
// BUILD ACTIVITY FEED
// ============================================================

function buildActivities() {
    activities = realAlerts.slice(0, 6).map(alert => {
        const severity = String(alert.severity || 'INFO').toUpperCase();

        let icon = 'fa-bell';
        let color = 'blue';

        if (severity === 'CRITICAL') {
            icon = 'fa-skull-crossbones';
            color = 'red';
        } else if (severity === 'HIGH') {
            icon = 'fa-shield-halved';
            color = 'orange';
        } else if (severity === 'MEDIUM') {
            icon = 'fa-triangle-exclamation';
            color = 'yellow';
        }

        return {
            icon,
            color,
            desc: safeText(alert.alert_type, 'Security Alert'),
            sub: safeText(
                alert.description,
                'Detection generated by SIEM analyzer'
            ),
            time: SiemEngine.formatTimeAgo(alert.timestamp),
            raw: alert
        };
    });
}

// ============================================================
// UPDATE DASHBOARD STATISTICS
// ============================================================

function updateDashboardStats() {
    const totalLogs = safeNumber(
        realStats?.total_logs,
        realLogs.length
    );

    const totalAlerts = safeNumber(
        realStats?.total_alerts,
        realAlerts.length
    );

    const criticalAlerts = safeNumber(
        realStats?.critical,
        realAlerts.filter(
            alert => String(alert?.severity || '').toUpperCase() === 'CRITICAL'
        ).length
    );

    const highAlerts = safeNumber(
        realStats?.high,
        realAlerts.filter(
            alert => String(alert?.severity || '').toUpperCase() === 'HIGH'
        ).length
    );

    const onlineAgents = realDevices.filter(
        device => String(device?.status || '').toLowerCase() === 'online'
    ).length;

    const totalAgents = realDevices.length;

    const elTotalLogs = document.getElementById('totalLogs');

    if (elTotalLogs) {
        elTotalLogs.textContent = totalLogs === null
            ? '—'
            : Number(totalLogs).toLocaleString();
    }

    const elTotalAlerts = document.getElementById('totalAlerts');

    if (elTotalAlerts) {
        elTotalAlerts.textContent = totalAlerts === null
            ? '—'
            : Number(totalAlerts).toLocaleString();
    }

    const elCritical = document.getElementById('criticalAlerts');

    if (elCritical) {
        elCritical.textContent = criticalAlerts === null
            ? '—'
            : Number(criticalAlerts).toLocaleString();
    }

    const elActiveAgents = document.getElementById('activeAgents');

    if (elActiveAgents) {
        elActiveAgents.textContent = String(onlineAgents);
    }

    const elTotalDevices = document.getElementById('totalDevices');

    if (elTotalDevices) {
        elTotalDevices.textContent = String(totalAgents);
    }

    updateDefensePosture(
        criticalAlerts,
        highAlerts,
        onlineAgents,
        totalAgents
    );
}

// ============================================================
// DEFENSE POSTURE
// ============================================================

function updateDefensePosture(
    criticalAlerts,
    highAlerts,
    onlineAgents,
    totalAgents
) {
    const scoreEl = document.getElementById('defenseScore');
    const statusEl = document.getElementById('defenseStatus');

    if (!scoreEl) return;

    if (
        totalAgents === 0 &&
        realAlerts.length === 0 &&
        realLogs.length === 0
    ) {
        scoreEl.textContent = '—';
        scoreEl.className = 'stat-value text-muted';

        if (statusEl) {
            statusEl.textContent = 'No telemetry';
            statusEl.className = 'stat-change';
        }

        return;
    }

    const agentAvailability = totalAgents > 0
        ? onlineAgents / totalAgents
        : 0;

    let score = agentAvailability * 100;

    if (criticalAlerts > 0) {
        score -= Math.min(50, criticalAlerts * 2);
    }

    if (highAlerts > 0) {
        score -= Math.min(30, highAlerts);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    scoreEl.textContent = `${score}%`;

    if (score >= 80) {
        scoreEl.className = 'stat-value text-green';

        if (statusEl) {
            statusEl.textContent = 'Operational';
            statusEl.className = 'stat-change up';
        }
    } else if (score >= 50) {
        scoreEl.className = 'stat-value text-orange';

        if (statusEl) {
            statusEl.textContent = 'Elevated Risk';
            statusEl.className = 'stat-change warning';
        }
    } else {
        scoreEl.className = 'stat-value text-red';

        if (statusEl) {
            statusEl.textContent = 'Critical Risk';
            statusEl.className = 'stat-change down';
        }
    }
}

// ============================================================
// RENDER RECENT ALERTS
// ============================================================

function renderAlertsList() {
    const container = document.getElementById('recentAlerts');
    if (!container) return;

    if (realAlerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding:20px;">
                <i class="fas fa-circle-info"
                   style="color:var(--text-muted)"></i>
                <h3>No alert telemetry</h3>
                <p>No alerts were returned by the SIEM API.</p>
            </div>`;
        return;
    }

    container.innerHTML = realAlerts.slice(0, 5).map(alert => {
        const alertId = alert?.id ?? '';
        const severityColor = SiemEngine.getSeverityColor(alert?.severity);

        return `
            <div class="alert-item"
                 onclick="openAlertModal(${JSON.stringify(String(alertId))})"
                 style="cursor:pointer;"
                 title="Click to investigate alert">
                <span class="alert-severity"
                      style="background:${severityColor};"></span>
                <div class="alert-info">
                    <div class="type">
                        ${SiemEngine.escapeHtml(
                            safeText(alert?.alert_type, 'Security Alert')
                        )}
                    </div>
                    <div class="source">
                        <i class="fas fa-server" style="font-size:0.6rem"></i>
                        ${SiemEngine.escapeHtml(
                            safeText(alert?.agent_id, 'Unknown')
                        )}
                        ·
                        <code>${SiemEngine.escapeHtml(
                            safeText(alert?.source_ip, '—')
                        )}</code>
                    </div>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    ${SiemEngine.getSeverityBadge(alert?.severity)}
                    <span class="alert-time">
                        ${SiemEngine.formatTimeAgo(alert?.timestamp)}
                    </span>
                </div>
            </div>`;
    }).join('');
}

// ============================================================
// RENDER DEVICE CARDS
// ============================================================

function renderDeviceCards() {
    const container = document.getElementById('deviceCards');
    if (!container) return;

    if (realDevices.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding:20px;">
                <i class="fas fa-server"></i>
                <h3>No Endpoint Telemetry</h3>
                <p>No agents were returned by the SIEM API.</p>
            </div>`;
        return;
    }

    container.innerHTML = realDevices.slice(0, 6).map(device => {
        const location = [
            device.city,
            device.country
        ].filter(Boolean).join(', ');

        return `
            <div class="device-card"
                 onclick="location.href='devices.html'">
                <div class="device-header">
                    <span class="device-name">
                        <i class="fas ${device.icon || 'fa-server'}"></i>
                        ${SiemEngine.escapeHtml(
                            safeText(device.name, 'Unknown Agent')
                        )}
                    </span>
                    ${SiemEngine.getStatusBadge(device.status)}
                </div>
                <div class="device-detail">
                    ${location ? `
                        <i class="fas fa-location-dot"></i>
                        ${SiemEngine.escapeHtml(location)}<br>
                    ` : ''}
                    ${device.os ? `
                        <i class="fas fa-microchip"></i>
                        ${SiemEngine.escapeHtml(device.os)}<br>
                    ` : ''}
                    ${device.ip ? `
                        <i class="fas fa-network-wired"></i>
                        <code>${SiemEngine.escapeHtml(device.ip)}</code>
                    ` : ''}
                </div>
            </div>`;
    }).join('');
}

// ============================================================
// RENDER TOP ATTACK TYPES
// ============================================================

function renderTopAttacks() {
    const container = document.getElementById('topAttacks');
    if (!container) return;

    const counts = {};

    realAlerts.forEach(alert => {
        const type = safeText(alert?.alert_type, 'Unknown Detection');
        counts[type] = (counts[type] || 0) + 1;
    });

    const sorted = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    if (sorted.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding:15px;">
                <p>No attack telemetry</p>
            </div>`;
        return;
    }

    const max = sorted[0][1];
    const colors = ['#ff4757', '#ff9f43', '#facc15', '#38bdf8', '#00f5a0'];

    container.innerHTML = sorted.map(([name, count], index) => {
        const width = max > 0 ? (count / max) * 100 : 0;

        return `
            <div class="attack-bar">
                <span class="attack-label"
                      title="${SiemEngine.escapeHtml(name)}">
                    ${SiemEngine.escapeHtml(name)}
                </span>
                <div class="attack-track">
                    <div class="attack-fill"
                         style="width:${width}%;
                                background:${colors[index % colors.length]};">
                    </div>
                </div>
                <span class="attack-value">${count}</span>
            </div>`;
    }).join('');
}

// ============================================================
// RENDER OS DISTRIBUTION
// ============================================================

function renderOSDistribution() {
    const container = document.getElementById('osDistribution');
    if (!container) return;

    const counts = {};

    realDevices.forEach(device => {
        if (!device.os) return;

        const os = String(device.os).trim();
        if (!os) return;

        counts[os] = (counts[os] || 0) + 1;
    });

    const sorted = Object.entries(counts)
        .sort((a, b) => b[1] - a[1]);

    if (sorted.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding:15px;">
                <p>No OS telemetry</p>
            </div>`;
        return;
    }

    const max = sorted[0][1];
    const colors = ['#00f5a0', '#38bdf8', '#a855f7', '#ff9f43'];

    container.innerHTML = sorted.map(([os, count], index) => {
        const width = max > 0 ? (count / max) * 100 : 0;

        return `
            <div class="os-item">
                <span class="os-label">
                    ${SiemEngine.escapeHtml(os)}
                </span>
                <div class="os-track">
                    <div class="os-fill"
                         style="width:${width}%;
                                background:${colors[index % colors.length]};">
                    </div>
                </div>
                <span class="os-value">${count}</span>
            </div>`;
    }).join('');
}

// ============================================================
// RENDER RECENT ACTIVITIES
// ============================================================

function renderRecentActivities() {
    const container = document.getElementById('recentActivities');
    if (!container) return;

    if (activities.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding:15px;">
                <p>No recent activity</p>
            </div>`;
        return;
    }

    container.innerHTML = activities.map(activity => `
        <div class="activity-item">
            <div class="activity-icon ${activity.color}">
                <i class="fas ${activity.icon}"></i>
            </div>
            <div class="activity-text">
                <div class="desc">
                    ${SiemEngine.escapeHtml(activity.desc)}
                </div>
                <div class="time">
                    ${SiemEngine.escapeHtml(activity.sub)}
                </div>
            </div>
            <span class="activity-badge">
                ${SiemEngine.escapeHtml(activity.time)}
            </span>
        </div>
    `).join('');
}

// ============================================================
// DASHBOARD MAP — LEAFLET + OPENSTREETMAP
// No Mapbox token required.
// ============================================================

function initDashboardMap() {
    const container = document.getElementById('worldMap');

    if (!container) {
        console.error('[Dashboard Map] #worldMap not found.');
        return;
    }

    if (typeof L === 'undefined') {
        console.error('[Dashboard Map] Leaflet is missing. Check index.html.');
        container.innerHTML = `
            <div style="padding:20px;color:#ff4757;">
                Leaflet failed to load. Check your internet connection.
            </div>`;
        return;
    }

    if (mapInstance) {
        mapInstance.invalidateSize();

        if (mapLoaded) {
            renderDashboardMap();
        }

        return;
    }

    try {
        mapInstance = L.map(container, {
            center: [20, 20],
            zoom: 2,
            minZoom: 1,
            maxZoom: 18,
            worldCopyJump: true
        });

        L.tileLayer(
            'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
            {
                subdomains: ['a', 'b', 'c'],
                maxZoom: 19,
                attribution:
                    '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap contributors</a>'
            }
        ).addTo(mapInstance);

        mapInstance.whenReady(() => {
            mapLoaded = true;
            mapInstance.invalidateSize();
            renderDashboardMap();

            console.log(
                '[Dashboard Map] Leaflet and OSM layer initialized.'
            );
        });

        mapInstance.on('tileerror', event => {
            console.error('[Dashboard Map] OSM tile failed:', event);
        });
    } catch (error) {
        console.error('[Dashboard Map] Initialization failed:', error);

        mapInstance = null;
        mapLoaded = false;
    }
}

// ============================================================
// LEAFLET MARKER ICONS
// ============================================================

function createLeafletIcon(type) {
    const styles = {
        server: {
            color: '#a855f7',
            size: 13,
            shadow: '0 0 12px #a855f7'
        },
        agent: {
            color: '#00f5a0',
            size: 12,
            shadow: '0 0 10px #00f5a0'
        },
        threat: {
            color: '#ff4757',
            size: 12,
            shadow: '0 0 12px #ff4757'
        }
    };

    const style = styles[type] || styles.agent;

    return L.divIcon({
        className: 'dashboard-map-marker',
        html: `
            <div style="
                width:${style.size}px;
                height:${style.size}px;
                border-radius:50%;
                background:${style.color};
                border:2px solid #fff;
                box-shadow:${style.shadow};
            "></div>
        `,
        iconSize: [style.size + 4, style.size + 4],
        iconAnchor: [
            (style.size + 4) / 2,
            (style.size + 4) / 2
        ]
    });
}

// ============================================================
// CLEAR MAP OVERLAYS
// ============================================================

function clearDashboardMapOverlays() {
    dashboardMapMarkers.forEach(marker => {
        try {
            if (mapInstance && mapInstance.hasLayer(marker)) {
                mapInstance.removeLayer(marker);
            }
        } catch (_) {}
    });

    dashboardMapMarkers = [];

    dashboardMapLines.forEach(line => {
        try {
            if (mapInstance && mapInstance.hasLayer(line)) {
                mapInstance.removeLayer(line);
            }
        } catch (_) {}
    });

    dashboardMapLines = [];
}

// ============================================================
// MAP POPUP HELPERS
// ============================================================

function buildServerPopup(server) {
    if (!server) return '';

    const location = server.location || {};
    const city = location.city || location.city_name || null;
    const country = location.country || location.country_name || null;
    const ip = server.ip || null;

    return `
        <div style="font-family:Inter,sans-serif;color:#f0f4f8;min-width:180px;">
            <strong style="color:#a855f7;font-size:.85rem;">
                <i class="fas fa-server"></i> SIEM Core Server
            </strong>
            <div style="font-size:.7rem;margin-top:6px;color:#94a3b8;line-height:1.6;">
                ${city || country ? `
                    <strong>Location:</strong>
                    ${SiemEngine.escapeHtml(
                        [city, country].filter(Boolean).join(', ')
                    )}<br>
                ` : ''}
                ${ip ? `
                    <strong>IP:</strong>
                    <code>${SiemEngine.escapeHtml(ip)}</code><br>
                ` : ''}
                <strong>Source:</strong> Real SIEM telemetry
            </div>
        </div>`;
}

function buildAgentPopup(agent) {
    const location = [
        agent.city,
        agent.state,
        agent.country
    ].filter(Boolean).join(', ');

    const agentName =
        agent.agent_id || agent.id || agent.name || 'Agent';

    return `
        <div style="font-family:Inter,sans-serif;color:#f0f4f8;min-width:180px;">
            <strong style="color:#00f5a0;font-size:.85rem;">
                <i class="fas ${agent.icon || 'fa-server'}"></i>
                ${SiemEngine.escapeHtml(safeText(agentName, 'Agent'))}
            </strong>
            <div style="font-size:.7rem;margin-top:6px;color:#94a3b8;line-height:1.6;">
                ${location ? `
                    <strong>Location:</strong>
                    ${SiemEngine.escapeHtml(location)}<br>
                ` : ''}
                ${agent.ip ? `
                    <strong>IP:</strong>
                    <code>${SiemEngine.escapeHtml(agent.ip)}</code><br>
                ` : ''}
                ${agent.os ? `
                    <strong>OS:</strong>
                    ${SiemEngine.escapeHtml(agent.os)}<br>
                ` : ''}
                ${agent.status ? `
                    <strong>Status:</strong>
                    ${SiemEngine.escapeHtml(agent.status)}
                ` : ''}
            </div>
        </div>`;
}

function buildThreatPopup(threat) {
    return `
        <div style="font-family:Inter,sans-serif;color:#f0f4f8;min-width:190px;">
            <strong style="color:#ff4757;font-size:.85rem;">
                <i class="fas fa-skull-crossbones"></i>
                Threat Actor
            </strong>
            <div style="font-size:.7rem;margin-top:6px;color:#94a3b8;line-height:1.6;">
                ${threat.ip ? `
                    <strong>IP:</strong>
                    <code>${SiemEngine.escapeHtml(threat.ip)}</code><br>
                ` : ''}
                ${threat.city || threat.country ? `
                    <strong>Origin:</strong>
                    ${SiemEngine.escapeHtml(
                        [threat.city, threat.country].filter(Boolean).join(', ')
                    )}<br>
                ` : ''}
                ${threat.type ? `
                    <strong>Attack:</strong>
                    ${SiemEngine.escapeHtml(threat.type)}<br>
                ` : ''}
                ${threat.severity ? `
                    <strong>Severity:</strong>
                    ${SiemEngine.escapeHtml(threat.severity)}
                ` : ''}
            </div>
        </div>`;
}

// ============================================================
// RENDER THREAT MAP
// ============================================================

function renderDashboardMap() {
    if (!mapInstance || !mapLoaded) return;

    clearDashboardMapOverlays();

    const server = realThreatMap.server;

    // SERVER MARKER
    if (
        server &&
        server.location &&
        hasCoordinates(server.location)
    ) {
        const marker = L.marker(
            [
                getLatitude(server.location),
                getLongitude(server.location)
            ],
            { icon: createLeafletIcon('server') }
        ).addTo(mapInstance);

        marker.bindPopup(buildServerPopup(server), { maxWidth: 280 });
        dashboardMapMarkers.push(marker);
    }

    // ENDPOINT AGENTS
    const agents = Array.isArray(realThreatMap.agents)
        ? realThreatMap.agents
        : [];

    agents.forEach(agent => {
        if (!hasCoordinates(agent)) return;

        const normalizedAgent = {
            ...agent,
            ip: agent.ip_address ?? agent.ip ?? null
        };

        const marker = L.marker(
            [getLatitude(agent), getLongitude(agent)],
            { icon: createLeafletIcon('agent') }
        ).addTo(mapInstance);

        marker.bindPopup(buildAgentPopup(normalizedAgent), {
            maxWidth: 280
        });

        dashboardMapMarkers.push(marker);
    });

    // THREAT MARKERS AND ATTACK LINES
    const threats = Array.isArray(realThreatMap.threats)
        ? realThreatMap.threats
        : [];

    threats.forEach(threat => {
        if (!hasCoordinates(threat)) return;

        const marker = L.marker(
            [getLatitude(threat), getLongitude(threat)],
            { icon: createLeafletIcon('threat') }
        ).addTo(mapInstance);

        marker.bindPopup(buildThreatPopup(threat), {
            maxWidth: 280
        });

        dashboardMapMarkers.push(marker);

        let targetLat = safeNumber(threat.target_lat);
        let targetLon = safeNumber(threat.target_lon);

        // Use API-provided target coordinates when available.
        // Otherwise, use the server coordinates supplied by the API.
        if (
            (targetLat === null || targetLon === null) &&
            server &&
            server.location &&
            hasCoordinates(server.location)
        ) {
            targetLat = getLatitude(server.location);
            targetLon = getLongitude(server.location);
        }

        if (targetLat === null || targetLon === null) return;

        const line = L.polyline(
            [
                [getLatitude(threat), getLongitude(threat)],
                [targetLat, targetLon]
            ],
            {
                color: '#ff3158',
                weight: 1.5,
                opacity: 0.75,
                dashArray: '5, 8'
            }
        ).addTo(mapInstance);

        dashboardMapLines.push(line);
    });

    updateDashboardMapStatus();
}

// ============================================================
// MAP STATUS
// ============================================================

function updateDashboardMapStatus() {
    const threatCount = Array.isArray(realThreatMap.threats)
        ? realThreatMap.threats.length
        : 0;

    const agentCount = Array.isArray(realThreatMap.agents)
        ? realThreatMap.agents.length
        : 0;

    const mapStatus = document.getElementById('mapStatus');

    if (mapStatus) {
        mapStatus.textContent =
            `${agentCount} endpoints · ${threatCount} threats`;
    }
}

// ============================================================
// MAP RESIZE
// ============================================================

function resizeDashboardMap() {
    if (!mapInstance) return;

    setTimeout(() => {
        try {
            mapInstance.invalidateSize();
        } catch (_) {}
    }, 100);
}

// ============================================================
// ALERT MODAL
// ============================================================

function openAlertModal(alertId) {
    const normalizedId = String(alertId);

    const alert = realAlerts.find(item =>
        String(item?.id) === normalizedId
    );

    if (!alert) return;

    const modal = document.getElementById('incidentModal');
    const content = document.getElementById('incidentModalContent');

    if (!modal || !content) return;

    const sourceIp = alert.source_ip || null;

    content.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;">
            <div>
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                    ${SiemEngine.getSeverityBadge(alert.severity)}
                    ${alert.id !== undefined ? `
                        <span class="siem-badge"
                              style="background:var(--bg-hover);color:var(--text-muted);">
                            ${SiemEngine.escapeHtml(String(alert.id))}
                        </span>
                    ` : ''}
                    ${alert.rule_id ? `
                        <span class="siem-badge"
                              style="background:rgba(56,189,248,.1);color:var(--blue);">
                            ${SiemEngine.escapeHtml(alert.rule_id)}
                        </span>
                    ` : ''}
                </div>
                <h3 style="font-size:1.15rem;font-weight:700;color:var(--text-primary);">
                    ${SiemEngine.escapeHtml(
                        safeText(alert.alert_type, 'Security Alert')
                    )}
                </h3>
            </div>
            <button class="modal-close-btn" onclick="closeAlertModal()">
                <i class="fas fa-times"></i>
            </button>
        </div>

        <div style="background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:var(--radius);padding:14px;margin-bottom:16px;font-size:.78rem;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:10px;">
                <div>
                    <span style="color:var(--text-muted);font-size:.65rem;text-transform:uppercase;">Affected Asset</span><br>
                    <strong>${SiemEngine.escapeHtml(safeText(alert.agent_id, '—'))}</strong>
                </div>
                <div>
                    <span style="color:var(--text-muted);font-size:.65rem;text-transform:uppercase;">Source IP</span><br>
                    <code>${SiemEngine.escapeHtml(safeText(sourceIp, '—'))}</code>
                </div>
                <div>
                    <span style="color:var(--text-muted);font-size:.65rem;text-transform:uppercase;">Detection Timestamp</span><br>
                    ${SiemEngine.escapeHtml(SiemEngine.formatDate(alert.timestamp))}
                </div>
                <div>
                    <span style="color:var(--text-muted);font-size:.65rem;text-transform:uppercase;">Status</span><br>
                    ${SiemEngine.getStatusBadge(alert.status)}
                </div>
            </div>
            <div>
                <span style="color:var(--text-muted);font-size:.65rem;text-transform:uppercase;">Description</span>
                <p style="margin-top:3px;color:var(--text-primary);line-height:1.5;">
                    ${SiemEngine.escapeHtml(
                        safeText(alert.description, 'No description returned by the SIEM.')
                    )}
                </p>
            </div>
        </div>

        <div style="display:flex;justify-content:flex-end;gap:10px;">
            <button class="action-btn"
                    onclick="SiemEngine.showToast('Investigation workflow is not connected to a backend action yet.','info','Investigation');closeAlertModal();">
                <i class="fas fa-play text-orange"></i>
                Start Investigation
            </button>
            <button class="filter-btn"
                    onclick="SiemEngine.showToast('Alert status update requires the backend alert-management endpoint.','info','Backend Action');closeAlertModal();">
                <i class="fas fa-check"></i>
                Resolve
            </button>
        </div>
    `;

    modal.classList.add('show');
}

// ============================================================
// CLOSE ALERT MODAL
// ============================================================

function closeAlertModal() {
    const modal = document.getElementById('incidentModal');

    if (modal) {
        modal.classList.remove('show');
    }
}

// ============================================================
// QUICK ACTION — FIM
// ============================================================

async function runFimScan() {
    try {
        const fim = await SiemEngine.fetchAPI('/api/fim');

        if (Array.isArray(fim)) {
            SiemEngine.showToast(
                `Received ${fim.length.toLocaleString()} FIM events from the SIEM.`,
                'info',
                'FIM Telemetry'
            );
        } else {
            SiemEngine.showToast(
                'FIM telemetry is currently unavailable.',
                'warning',
                'FIM'
            );
        }
    } catch (error) {
        console.error('[Dashboard] FIM request failed:', error);

        SiemEngine.showToast(
            'Unable to retrieve FIM telemetry.',
            'warning',
            'FIM'
        );
    }
}

// ============================================================
// QUICK ACTION — BLOCK ATTACKER
// ============================================================

async function blockAttackerIP() {
    const threat = realThreatMap.threats?.find(
        item => item && item.ip
    );

    if (!threat) {
        SiemEngine.showToast(
            'No real threat IP is currently available to quarantine.',
            'warning',
            'No Threat IP'
        );
        return;
    }

    SiemEngine.showToast(
        `Threat IP ${threat.ip} identified. Backend quarantine action is not exposed by the current API.`,
        'info',
        'Threat Identified'
    );
}

// ============================================================
// EXPORT SOC BRIEF
// ============================================================

function exportSocBrief() {
    if (realAlerts.length === 0) {
        SiemEngine.showToast(
            'There are no real alerts to export.',
            'warning',
            'Nothing to Export'
        );
        return;
    }

    const rows = realAlerts.map(alert => [
        alert.id ?? '',
        alert.timestamp ?? '',
        alert.agent_id ?? '',
        alert.alert_type ?? '',
        alert.severity ?? '',
        alert.status ?? '',
        alert.source_ip ?? ''
    ]);

    const date = new Date().toISOString().substring(0, 10);

    SiemEngine.exportToCSV(
        `siem_soc_brief_${date}.csv`,
        rows,
        [
            'ID',
            'Timestamp',
            'Asset',
            'Threat',
            'Severity',
            'Status',
            'Attacker IP'
        ]
    );
}

// ============================================================
// SIMULATE ATTACK — DISABLED
// ============================================================

function simulateAttack() {
    SiemEngine.showToast(
        'Simulation is disabled. This dashboard displays SIEM telemetry only.',
        'info',
        'Real Data Mode'
    );
}

// ============================================================
// TOGGLE LIVE REFRESH
// ============================================================

function toggleLive() {
    const badge = document.getElementById('liveBadge');
    const label = document.getElementById('liveLabel');

    isLive = !isLive;

    if (isLive) {
        if (badge) badge.classList.remove('paused');
        if (label) label.textContent = 'LIVE';

        if (liveInterval) {
            clearInterval(liveInterval);
        }

        liveInterval = setInterval(loadDashboard, 15000);

        SiemEngine.showToast(
            'Real-time telemetry refresh enabled.',
            'success',
            'LIVE'
        );

        loadDashboard();
    } else {
        if (badge) badge.classList.add('paused');
        if (label) label.textContent = 'PAUSED';

        if (liveInterval) {
            clearInterval(liveInterval);
            liveInterval = null;
        }

        SiemEngine.showToast(
            'Automatic telemetry refresh paused.',
            'info',
            'LIVE'
        );
    }
}

// ============================================================
// MASTER DASHBOARD LOADER
// ============================================================

async function loadDashboard() {
    const refreshIcon = document.getElementById('refreshIcon');

    if (refreshIcon) {
        refreshIcon.classList.add('fa-spin');
    }

    try {
        await fetchDashboardData();

        updateDashboardStats();
        renderAlertsList();
        renderDeviceCards();
        renderTopAttacks();
        renderOSDistribution();
        renderRecentActivities();

        if (!mapInstance) {
            initDashboardMap();
        } else if (mapLoaded) {
            renderDashboardMap();
        }

        SiemEngine.updateLastUpdate(
            realThreatMap.timestamp || null
        );
    } catch (error) {
        console.error('[Dashboard] Load failed:', error);
    } finally {
        if (refreshIcon) {
            setTimeout(() => {
                refreshIcon.classList.remove('fa-spin');
            }, 400);
        }
    }
}

// ============================================================
// WINDOW RESIZE
// ============================================================

window.addEventListener('resize', () => {
    resizeDashboardMap();
});

// ============================================================
// MODAL BACKGROUND CLOSE
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('incidentModal');

    if (modal) {
        modal.onclick = event => {
            if (event.target === modal) {
                closeAlertModal();
            }
        };
    }
});

// ============================================================
// INITIALIZE DASHBOARD
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {
    await loadDashboard();

    if (isLive) {
        liveInterval = setInterval(loadDashboard, 15000);
    }
});

// ============================================================
// PUBLIC GLOBAL API
// ============================================================

window.DashboardSIEM = {
    load: loadDashboard,
    refresh: loadDashboard,
    getDevices: () => realDevices,
    getAlerts: () => realAlerts,
    getLogs: () => realLogs,
    getStats: () => realStats,
    getThreatMap: () => realThreatMap,
    getMap: () => mapInstance
};
