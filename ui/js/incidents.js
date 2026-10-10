
/* =========================================================
   MY SIEM — INCIDENT MANAGEMENT
   Real API data | Search | Filters | Pagination | Details
   ========================================================= */

const INCIDENTS_API_BASE =
    window.SIEM_API_BASE || window.location.origin;

const INCIDENTS_PAGE_SIZE = 10;

let allIncidents = [];
let filteredIncidents = [];
let currentPage = 1;
let incidentsSource = "/api/incidents";

/* ---------- Helpers ---------- */

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
}

function getElement(id) {
    return document.getElementById(id);
}

async function fetchIncidentAPI(endpoint, options = {}) {
    const response = await fetch(
        `${INCIDENTS_API_BASE}${endpoint}`,
        {
            cache: "no-store",
            ...options,
            headers: {
                Accept: "application/json",
                ...(options.body ? { "Content-Type": "application/json" } : {}),
                ...(options.headers || {})
            }
        }
    );

    const contentType = response.headers.get("content-type") || "";
    let data = null;

    if (contentType.includes("application/json")) {
        data = await response.json();
    } else {
        data = await response.text();
    }

    if (!response.ok) {
        const message =
            typeof data === "object" && data
                ? data.error || data.message || `HTTP ${response.status}`
                : `HTTP ${response.status}`;

        const error = new Error(message);
        error.status = response.status;
        throw error;
    }

    return data;
}

function normalizeArrayResponse(data) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.incidents)) return data.incidents;
    if (data && Array.isArray(data.alerts)) return data.alerts;
    if (data && Array.isArray(data.data)) return data.data;
    if (data && Array.isArray(data.results)) return data.results;
    return [];
}

function normalizeSeverity(value) {
    const severity = String(value || "MEDIUM").trim().toUpperCase();
    const aliases = {
        "SEV-1": "CRITICAL",
        "SEV-2": "HIGH",
        "SEV-3": "MEDIUM",
        "SEV-4": "LOW",
        "WARNING": "MEDIUM",
        "INFORMATIONAL": "INFO"
    };

    const normalized = aliases[severity] || severity;
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(normalized)
        ? normalized
        : "MEDIUM";
}

function normalizeStatus(value) {
    const status = String(value || "OPEN").trim().toUpperCase()
        .replace(/[\s-]+/g, "_");

    const aliases = {
        "NEW": "OPEN",
        "ACTIVE": "OPEN",
        "PENDING": "OPEN",
        "IN_PROGRESS": "IN_PROGRESS",
        "INVESTIGATION": "INVESTIGATING",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
        "MITIGATED": "RESOLVED"
    };

    const normalized = aliases[status] || status;
    return [
        "OPEN",
        "IN_PROGRESS",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "CLOSED",
        "FALSE_POSITIVE"
    ].includes(normalized) ? normalized : "OPEN";
}

function normalizeIncident(item, index) {
    const timestamp =
        item.timestamp ??
        item.created_at ??
        item.createdAt ??
        item.time ??
        item.detected_at ??
        "";

    return {
        id: String(
            item.id ??
            item.incident_id ??
            item.alert_id ??
            item.event_id ??
            `UNIDENTIFIED-${index + 1}`
        ),
        title: String(
            item.title ??
            item.alert_type ??
            item.rule_name ??
            item.type ??
            item.event_type ??
            "Security Event"
        ),
        type: String(
            item.type ??
            item.alert_type ??
            item.rule_name ??
            item.event_type ??
            item.title ??
            "Security Event"
        ),
        severity: normalizeSeverity(item.severity ?? item.level ?? item.priority),
        status: normalizeStatus(item.status ?? item.state),
        agent_id: String(
            item.agent_id ??
            item.agent ??
            item.hostname ??
            item.host ??
            item.device_name ??
            "Unknown"
        ),
        description: String(
            item.description ??
            item.message ??
            item.details ??
            "No description provided by the backend."
        ),
        timestamp,
        source_ip: String(
            item.source_ip ??
            item.src_ip ??
            item.sourceIp ??
            item.src ??
            item.ip_address ??
            "Unknown"
        ),
        rule_id: String(
            item.rule_id ??
            item.rule_name ??
            item.rule ??
            item.signature ??
            "Unknown"
        ),
        assigned_to: String(item.assigned_to ?? item.assignee ?? "Unassigned"),
        affected_assets: item.affected_assets ?? item.affectedAssets ?? 1,
        raw: item
    };
}

function parseIncidentDate(value) {
    if (!value) return null;

    let date = new Date(value);

    if (Number.isNaN(date.getTime()) && typeof value === "string") {
        date = new Date(value.replace(" ", "T") + "Z");
    }

    return Number.isNaN(date.getTime()) ? null : date;
}

function formatIncidentDate(value) {
    const date = parseIncidentDate(value);
    return date ? date.toLocaleString() : (value ? String(value) : "Unknown");
}

function timeAgo(value) {
    const date = parseIncidentDate(value);
    if (!date) return "—";

    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));

    if (seconds < 60) return "Just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

/* ---------- Theme ---------- */

function toggleTheme() {
    const body = document.body;
    const isLight = body.getAttribute("data-theme") === "light";
    const label = getElement("themeLabel");
    const icon = getElement("themeToggle")?.querySelector("i");

    if (isLight) {
        body.removeAttribute("data-theme");
        if (label) label.textContent = "Dark";
        if (icon) icon.className = "fas fa-moon";
        try { localStorage.setItem("siem_theme", "dark"); } catch (_) {}
    } else {
        body.setAttribute("data-theme", "light");
        if (label) label.textContent = "Light";
        if (icon) icon.className = "fas fa-sun";
        try { localStorage.setItem("siem_theme", "light"); } catch (_) {}
    }
}

function loadTheme() {
    let theme = "dark";

    try {
        theme = localStorage.getItem("siem_theme") || "dark";
    } catch (_) {}

    const label = getElement("themeLabel");
    const icon = getElement("themeToggle")?.querySelector("i");

    if (theme === "light") {
        document.body.setAttribute("data-theme", "light");
        if (label) label.textContent = "Light";
        if (icon) icon.className = "fas fa-sun";
    } else {
        document.body.removeAttribute("data-theme");
        if (label) label.textContent = "Dark";
        if (icon) icon.className = "fas fa-moon";
    }
}

/* ---------- Load real data ---------- */

async function requestIncidents() {
    try {
        incidentsSource = "/api/incidents";
        return await fetchIncidentAPI("/api/incidents");
    } catch (error) {
        // The documented backend may expose alerts but not incidents.
        // Only fall back when the incident route is missing.
        if (error.status !== 404) throw error;
    }

    incidentsSource = "/api/alerts";
    return await fetchIncidentAPI("/api/alerts");
}

async function loadIncidents(options = {}) {
    const tbody = getElement("incidentsBody");
    const silent = options.silent === true;

    if (!silent && tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="loading-text">
                    <i class="fas fa-spinner fa-spin text-green"></i>
                    Loading data from the SIEM backend...
                </td>
            </tr>`;
    }

    try {
        const data = await requestIncidents();

        allIncidents = normalizeArrayResponse(data)
            .map(normalizeIncident)
            .filter(item => item.id && !item.id.startsWith("UNIDENTIFIED-"));

        allIncidents.sort((a, b) => {
            const dateA = parseIncidentDate(a.timestamp)?.getTime() || 0;
            const dateB = parseIncidentDate(b.timestamp)?.getTime() || 0;
            return dateB - dateA;
        });

        applyIncidentFilters();
        updateIncidentStats();
        updateLastUpdate();
        showIncidentConnectionStatus(
            `Connected · Source: ${incidentsSource}`,
            true
        );
    } catch (error) {
        console.error("[MY SIEM] Could not load incidents:", error);

        allIncidents = [];
        filteredIncidents = [];
        updateIncidentStats();
        updatePagination();

        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8">
                        <div class="empty-state">
                            <i class="fas fa-triangle-exclamation"
                               style="color:var(--red);font-size:2rem"></i>
                            <h3>Unable to load incidents</h3>
                            <p>${escapeHtml(error.message)}</p>
                            <small>
                                Checked /api/incidents and, if missing,
                                /api/alerts. Verify the backend URL and API routes.
                            </small>
                            <br><br>
                            <button class="filter-btn" type="button"
                                    onclick="loadIncidents()">
                                <i class="fas fa-rotate"></i> Retry
                            </button>
                        </div>
                    </td>
                </tr>`;
        }

        showIncidentConnectionStatus("Backend API unavailable", false);
    }
}

function showIncidentConnectionStatus(message, success) {
    const status = getElement("statusBarRight");
    if (!status) return;

    status.textContent = message;
    status.style.color = success ? "var(--green)" : "var(--red)";
}

function updateLastUpdate() {
    const now = new Date().toLocaleTimeString();
    const lastUpdate = getElement("lastUpdate");
    const status = getElement("statusBarRight");

    if (lastUpdate) lastUpdate.textContent = `Last update: ${now}`;
    if (status) {
        status.textContent = `Last scan: ${now}`;
        status.style.color = "var(--text-secondary)";
    }
}

/* ---------- Statistics ---------- */

function updateIncidentStats() {
    const openStatuses = ["OPEN", "IN_PROGRESS", "INVESTIGATING", "CONTAINED"];
    const closedStatuses = ["RESOLVED", "CLOSED", "FALSE_POSITIVE"];

    const counts = {
        incidentTotal: allIncidents.length,
        incidentCritical: allIncidents.filter(x => x.severity === "CRITICAL").length,
        incidentHigh: allIncidents.filter(x => x.severity === "HIGH").length,
        incidentOpen: allIncidents.filter(x => openStatuses.includes(x.status)).length,
        incidentResolved: allIncidents.filter(x => closedStatuses.includes(x.status)).length
    };

    Object.entries(counts).forEach(([id, count]) => {
        const element = getElement(id);
        if (element) element.textContent = count;
    });

    const badge = getElement("alertBadge");
    if (badge) {
        badge.textContent = allIncidents.filter(x =>
            ["CRITICAL", "HIGH"].includes(x.severity) &&
            openStatuses.includes(x.status)
        ).length;
    }
}

/* ---------- Search and filters ---------- */

function populateAgentFilter() {
    const select = getElement("agentFilter");
    if (!select) return;

    const selected = select.value || "ALL";
    const agents = [...new Set(allIncidents.map(x => x.agent_id).filter(Boolean))].sort();

    select.innerHTML = '<option value="ALL">All Endpoints</option>';

    agents.forEach(agent => {
        const option = document.createElement("option");
        option.value = agent;
        option.textContent = agent;
        select.appendChild(option);
    });

    if (agents.includes(selected)) select.value = selected;
}

function searchIncidents() {
    currentPage = 1;
    applyIncidentFilters();
}

function applyIncidentFilters() {
    populateAgentFilter();

    const query = (getElement("searchInput")?.value || "").trim().toLowerCase();
    const severity = getElement("severityFilter")?.value || "ALL";
    const status = getElement("statusFilter")?.value || "ALL";
    const agent = getElement("agentFilter")?.value || "ALL";

    filteredIncidents = allIncidents.filter(item => {
        const searchable = [
            item.id,
            item.title,
            item.type,
            item.agent_id,
            item.description,
            item.source_ip,
            item.rule_id
        ].join(" ").toLowerCase();

        return (!query || searchable.includes(query)) &&
            (severity === "ALL" || item.severity === severity) &&
            (status === "ALL" || item.status === status) &&
            (agent === "ALL" || item.agent_id === agent);
    });

    renderIncidents();
    updatePagination();
}

function filterBySeverity(value) {
    const select = getElement("severityFilter");
    if (select) select.value = value || "ALL";
    searchIncidents();
}

function filterByStatus(value) {
    const select = getElement("statusFilter");
    if (select) select.value = value || "ALL";
    searchIncidents();
}

function resetFilters() {
    ["searchInput"].forEach(id => {
        const element = getElement(id);
        if (element) element.value = "";
    });

    ["severityFilter", "statusFilter", "agentFilter"].forEach(id => {
        const element = getElement(id);
        if (element) element.value = "ALL";
    });

    currentPage = 1;
    applyIncidentFilters();
}

/* ---------- Render table ---------- */

function renderIncidents() {
    const tbody = getElement("incidentsBody");
    if (!tbody) return;

    const start = (currentPage - 1) * INCIDENTS_PAGE_SIZE;
    const pageItems = filteredIncidents.slice(start, start + INCIDENTS_PAGE_SIZE);

    if (!pageItems.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8">
                    <div class="empty-state">
                        <i class="fas fa-shield-alt"
                           style="color:var(--green);font-size:2rem"></i>
                        <h3>No incidents found</h3>
                        <p>No backend records match the current filters.</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = pageItems.map((item, index) => {
        const detailId = `incident-detail-${start + index}`;
        const severityClass = item.severity.toLowerCase().replace(/[^a-z]/g, "");
        const statusClass = item.status.toLowerCase().replace(/[^a-z]/g, "");

        return `
        <tr>
            <td>
                <button class="expand-btn" type="button"
                        aria-label="Expand incident details"
                        onclick="toggleDetail('${detailId}')">
                    <i class="fas fa-chevron-down" id="icon-${detailId}"></i>
                </button>
            </td>
            <td><strong style="color:var(--blue)">${escapeHtml(item.id)}</strong></td>
            <td title="${escapeHtml(formatIncidentDate(item.timestamp))}">
                ${escapeHtml(timeAgo(item.timestamp))}
            </td>
            <td>${escapeHtml(item.type)}</td>
            <td><span class="badge badge-${severityClass}">${escapeHtml(item.severity)}</span></td>
            <td><span class="badge badge-${statusClass}">${escapeHtml(item.status.replace(/_/g, " "))}</span></td>
            <td><code>${escapeHtml(item.agent_id)}</code></td>
            <td>
                <button class="filter-btn" type="button"
                        onclick="viewIncident('${escapeHtml(item.id)}')">
                    <i class="fas fa-eye"></i> View
                </button>
                <button class="filter-btn" type="button"
                        onclick="updateStatus('${escapeHtml(item.id)}')">
                    <i class="fas fa-sync-alt"></i> Update
                </button>
            </td>
        </tr>
        <tr id="${detailId}" class="incident-detail-row">
            <td colspan="8">
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="label">Description</span>
                        <span class="value">${escapeHtml(item.description)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Source IP</span>
                        <span class="value">${escapeHtml(item.source_ip)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Rule</span>
                        <span class="value">${escapeHtml(item.rule_id)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Assigned To</span>
                        <span class="value">${escapeHtml(item.assigned_to)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Created At</span>
                        <span class="value">${escapeHtml(formatIncidentDate(item.timestamp))}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Endpoint</span>
                        <span class="value">${escapeHtml(item.agent_id)}</span>
                    </div>
                </div>
            </td>
        </tr>`;
    }).join("");
}

function toggleDetail(id) {
    const row = getElement(id);
    const icon = getElement(`icon-${id}`);
    if (!row) return;

    const opened = row.classList.toggle("show");
    if (icon) icon.className = opened
        ? "fas fa-chevron-up"
        : "fas fa-chevron-down";
}

/* ---------- Pagination ---------- */

function updatePagination() {
    const totalPages = Math.max(
        1,
        Math.ceil(filteredIncidents.length / INCIDENTS_PAGE_SIZE)
    );

    const pageInfo = getElement("pageInfo");
    const prev = getElement("prevPage");
    const next = getElement("nextPage");

    if (pageInfo) {
        pageInfo.textContent =
            `Showing ${filteredIncidents.length} incidents · Page ${currentPage} of ${totalPages}`;
    }

    if (prev) prev.disabled = currentPage <= 1;
    if (next) next.disabled = currentPage >= totalPages;
}

function changePage(delta) {
    const totalPages = Math.max(
        1,
        Math.ceil(filteredIncidents.length / INCIDENTS_PAGE_SIZE)
    );

    const nextPage = currentPage + delta;
    if (nextPage < 1 || nextPage > totalPages) return;

    currentPage = nextPage;
    renderIncidents();
    updatePagination();
}

/* ---------- Details modal ---------- */

function viewIncident(id) {
    const item = allIncidents.find(x => String(x.id) === String(id));
    if (!item) return;

    const modal = getElement("incidentModal");
    const content = getElement("incidentModalContent");
    if (!modal || !content) {
        alert(`Incident ${id}\n\n${item.description}`);
        return;
    }

    content.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
            <div>
                <small style="color:var(--text-muted)">INCIDENT DETAILS</small>
                <h2 style="margin:4px 0">${escapeHtml(item.id)}</h2>
            </div>
            <button class="filter-btn" type="button" onclick="closeIncidentModal()">
                <i class="fas fa-times"></i> Close
            </button>
        </div>

        <div class="detail-grid" style="margin-top:18px">
            <div class="detail-item"><span class="label">Threat Vector</span><span class="value">${escapeHtml(item.type)}</span></div>
            <div class="detail-item"><span class="label">Severity</span><span class="value">${escapeHtml(item.severity)}</span></div>
            <div class="detail-item"><span class="label">Status</span><span class="value">${escapeHtml(item.status.replace(/_/g, " "))}</span></div>
            <div class="detail-item"><span class="label">Endpoint</span><span class="value">${escapeHtml(item.agent_id)}</span></div>
            <div class="detail-item"><span class="label">Source IP</span><span class="value">${escapeHtml(item.source_ip)}</span></div>
            <div class="detail-item"><span class="label">Rule</span><span class="value">${escapeHtml(item.rule_id)}</span></div>
            <div class="detail-item"><span class="label">Created At</span><span class="value">${escapeHtml(formatIncidentDate(item.timestamp))}</span></div>
            <div class="detail-item"><span class="label">Assigned To</span><span class="value">${escapeHtml(item.assigned_to)}</span></div>
        </div>

        <div class="detail-item" style="margin-top:14px">
            <span class="label">Description</span>
            <span class="value">${escapeHtml(item.description)}</span>
        </div>

        <p style="margin-top:18px;color:var(--text-muted);font-size:.8rem">
            Data source: ${escapeHtml(incidentsSource)}
        </p>`;

    modal.classList.add("show");
    document.body.style.overflow = "hidden";
}

function closeIncidentModal() {
    getElement("incidentModal")?.classList.remove("show");
    document.body.style.overflow = "";
}

/* ---------- Backend-persistent status update ---------- */

async function updateStatus(id) {
    const item = allIncidents.find(x => String(x.id) === String(id));
    if (!item) return;

    const statuses = [
        "OPEN",
        "IN_PROGRESS",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "FALSE_POSITIVE"
    ];

    const currentIndex = statuses.indexOf(item.status);
    const nextStatus = statuses[(currentIndex + 1 + statuses.length) % statuses.length];

    if (!confirm(`Change ${item.id} from ${item.status} to ${nextStatus}?`)) {
        return;
    }

    try {
        // This requires a PATCH route implemented by the backend.
        // Do not report success unless the backend confirms the update.
        await fetchIncidentAPI(
            `/api/incidents/${encodeURIComponent(item.id)}/status`,
            {
                method: "PATCH",
                body: JSON.stringify({ status: nextStatus.toLowerCase() })
            }
        );

        await loadIncidents();
        alert(`Incident ${item.id} status updated.`);
    } catch (error) {
        console.error("[MY SIEM] Status update failed:", error);
        alert(
            "Could not update incident status.\n\n" +
            error.message +
            "\n\nThe backend must implement PATCH /api/incidents/<id>/status."
        );
    }
}

/* ---------- CSV export ---------- */

function exportIncidentsCSV() {
    if (!filteredIncidents.length) {
        alert("There are no incident records to export.");
        return;
    }

    const columns = [
        ["Case ID", "id"],
        ["Time", "timestamp"],
        ["Threat Vector", "type"],
        ["Severity", "severity"],
        ["Status", "status"],
        ["Endpoint", "agent_id"],
        ["Source IP", "source_ip"],
        ["Description", "description"]
    ];

    const quote = value =>
        `"${String(value ?? "").replace(/"/g, '""')}"`;

    const rows = [
        columns.map(column => quote(column[0])).join(","),
        ...filteredIncidents.map(item =>
            columns.map(column => quote(item[column[1]])).join(",")
        )
    ];

    const blob = new Blob(["\uFEFF" + rows.join("\r\n")], {
        type: "text/csv;charset=utf-8;"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `siem-incidents-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

/* ---------- Initialization ---------- */

document.addEventListener("DOMContentLoaded", () => {
    loadTheme();
    loadIncidents();

    getElement("searchInput")?.addEventListener("input", searchIncidents);
    getElement("severityFilter")?.addEventListener("change", searchIncidents);
    getElement("statusFilter")?.addEventListener("change", searchIncidents);
    getElement("agentFilter")?.addEventListener("change", searchIncidents);
    getElement("resetFilters")?.addEventListener("click", resetFilters);
    getElement("prevPage")?.addEventListener("click", () => changePage(-1));
    getElement("nextPage")?.addEventListener("click", () => changePage(1));

    getElement("incidentModal")?.addEventListener("click", event => {
        if (event.target === getElement("incidentModal")) closeIncidentModal();
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape") closeIncidentModal();
    });
});

/* Refresh real data every 15 seconds. */
setInterval(() => {
    if (!document.hidden) loadIncidents({ silent: true });
}, 15000);

/* Keep functions available to the HTML onclick handlers. */
window.loadIncidents = loadIncidents;
window.toggleTheme = toggleTheme;
window.searchIncidents = searchIncidents;
window.filterBySeverity = filterBySeverity;
window.filterByStatus = filterByStatus;
window.resetFilters = resetFilters;
window.changePage = changePage;
window.toggleDetail = toggleDetail;
window.viewIncident = viewIncident;
window.updateStatus = updateStatus;
window.closeIncidentModal = closeIncidentModal;
window.exportIncidentsCSV = exportIncidentsCSV;
