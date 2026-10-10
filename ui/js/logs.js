// ════════════════════════════════════════════════════════════
//  LOGS PAGE
//  100% REAL DATA | Search | Filter | Pagination | CSV
// ════════════════════════════════════════════════════════════

let allLogs = [];
let filteredLogs = [];
let currentPage = 1;

const pageSize = 15;

// ────────────────────────────────────────────────────────────
// API BASE
// ────────────────────────────────────────────────────────────

const LOGS_API_BASE =
    window.SIEM_API_BASE ||
    window.location.origin;


// ────────────────────────────────────────────────────────────
// SAFE HTML ESCAPE
// ────────────────────────────────────────────────────────────

function escapeHtml(value) {
    if (value === null || value === undefined) return '';

    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}


// ────────────────────────────────────────────────────────────
// API REQUEST
// ────────────────────────────────────────────────────────────

async function fetchLogsAPI(endpoint) {

    const response = await fetch(
        `${LOGS_API_BASE}${endpoint}`,
        {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            },
            cache: 'no-store'
        }
    );

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return await response.json();
}


// ────────────────────────────────────────────────────────────
// NORMALIZE API RESPONSE
// ────────────────────────────────────────────────────────────

function normalizeLogsResponse(data) {

    if (Array.isArray(data)) {
        return data;
    }

    if (data && Array.isArray(data.logs)) {
        return data.logs;
    }

    if (data && Array.isArray(data.data)) {
        return data.data;
    }

    return [];
}


// ────────────────────────────────────────────────────────────
// TIMESTAMP
// ────────────────────────────────────────────────────────────

function parseTimestamp(timestamp) {

    if (!timestamp) return null;

    const value = String(timestamp).trim();

    if (!value) return null;

    let date = new Date(value);

    if (Number.isNaN(date.getTime())) {

        date = new Date(
            value.replace(' ', 'T') + 'Z'
        );
    }

    if (Number.isNaN(date.getTime())) {
        return null;
    }

    return date;
}


// ────────────────────────────────────────────────────────────
// FORMAT DATE
// ────────────────────────────────────────────────────────────

function formatLogDate(timestamp) {

    const date = parseTimestamp(timestamp);

    if (!date) {
        return timestamp || '-';
    }

    return date.toLocaleString();
}


// ────────────────────────────────────────────────────────────
// TIME AGO
// ────────────────────────────────────────────────────────────

function formatTimeAgo(timestamp) {

    const date = parseTimestamp(timestamp);

    if (!date) return '-';

    const diff =
        Math.floor(
            (Date.now() - date.getTime()) / 1000
        );

    if (diff < 0) {
        return 'Just now';
    }

    if (diff < 60) {
        return 'Just now';
    }

    if (diff < 3600) {
        return `${Math.floor(diff / 60)}m ago`;
    }

    if (diff < 86400) {
        return `${Math.floor(diff / 3600)}h ago`;
    }

    return `${Math.floor(diff / 86400)}d ago`;
}


// ────────────────────────────────────────────────────────────
// LEVEL CLASS
// ────────────────────────────────────────────────────────────

function getLevelClass(level) {

    const value =
        String(level || 'INFO')
            .toUpperCase();

    switch (value) {

        case 'ERROR':
            return 'ERROR';

        case 'WARN':
        case 'WARNING':
            return 'WARN';

        case 'DEBUG':
            return 'DEBUG';

        case 'INFO':
        default:
            return 'INFO';
    }
}


// ────────────────────────────────────────────────────────────
// LOAD LOGS
// ────────────────────────────────────────────────────────────

async function loadLogs(options = {}) {

    const tbody =
        document.getElementById('logsBody');

    const silent =
        options.silent === true;

    if (!silent && tbody) {

        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="loading-text">
                    <i class="fas fa-spinner fa-spin"></i>
                    Fetching real logs from server...
                </td>
            </tr>
        `;
    }

    try {

        const data =
            await fetchLogsAPI('/api/logs');

        // IMPORTANT:
        // No sample data.
        // No fake fallback.
        // No generated logs.

        allLogs =
            normalizeLogsResponse(data);

        // Newest first
        allLogs.sort((a, b) => {

            const dateA =
                parseTimestamp(
                    a.timestamp
                )?.getTime() || 0;

            const dateB =
                parseTimestamp(
                    b.timestamp
                )?.getTime() || 0;

            return dateB - dateA;
        });

        populateAgentFilter();

        populateTypeFilter();

        applyFilters(false);

        updateLogStats();

        updateLastUpdate();

    } catch (error) {

        console.error(
            '[SIEM LOGS] Failed to load logs:',
            error
        );

        allLogs = [];
        filteredLogs = [];

        updateLogStats();

        updatePagination();

        if (tbody) {

            tbody.innerHTML = `
                <tr>
                    <td colspan="7">
                        <div class="empty-state">

                            <i
                                class="fas fa-triangle-exclamation"
                                style="color:var(--red);font-size:2rem;"
                            ></i>

                            <h3>Unable to load logs</h3>

                            <p>
                                Backend API is unavailable.
                            </p>

                            <small>
                                ${escapeHtml(error.message)}
                            </small>

                        </div>
                    </td>
                </tr>
            `;
        }
    }
}


// ────────────────────────────────────────────────────────────
// POPULATE AGENT FILTER
// ────────────────────────────────────────────────────────────

function populateAgentFilter() {

    const select =
        document.getElementById('agentFilter');

    if (!select) return;

    const currentValue =
        select.value || 'ALL';

    const agents = [
        ...new Set(
            allLogs
                .map(log => log.agent_id)
                .filter(Boolean)
        )
    ].sort();

    select.innerHTML =
        `<option value="ALL">All Agents</option>`;

    agents.forEach(agent => {

        const option =
            document.createElement('option');

        option.value = agent;

        option.textContent = agent;

        select.appendChild(option);
    });

    if (
        agents.includes(currentValue)
    ) {
        select.value = currentValue;
    }
}


// ────────────────────────────────────────────────────────────
// POPULATE TYPE FILTER
// ────────────────────────────────────────────────────────────

function populateTypeFilter() {

    const select =
        document.getElementById('typeFilter');

    if (!select) return;

    const currentValue =
        select.value || 'ALL';

    const types = [
        ...new Set(
            allLogs
                .map(log => log.log_type)
                .filter(Boolean)
        )
    ].sort();

    select.innerHTML =
        `<option value="ALL">All Types</option>`;

    types.forEach(type => {

        const option =
            document.createElement('option');

        option.value = type;

        option.textContent = type;

        select.appendChild(option);
    });

    if (
        types.includes(currentValue)
    ) {
        select.value = currentValue;
    }
}


// ────────────────────────────────────────────────────────────
// LOG STATISTICS
// ────────────────────────────────────────────────────────────

function updateLogStats() {

    const total =
        allLogs.length;

    const errors =
        allLogs.filter(
            log =>
                String(log.level || '')
                    .toUpperCase() === 'ERROR'
        ).length;

    const warnings =
        allLogs.filter(
            log =>
                ['WARN', 'WARNING'].includes(
                    String(log.level || '')
                        .toUpperCase()
                )
        ).length;

    const info =
        allLogs.filter(
            log => {

                const level =
                    String(
                        log.level || 'INFO'
                    ).toUpperCase();

                return level === 'INFO';
            }
        ).length;


    const totalElement =
        document.getElementById('logTotal');

    const errorElement =
        document.getElementById('logErrors');

    const warningElement =
        document.getElementById('logWarnings');

    const infoElement =
        document.getElementById('logInfo');


    if (totalElement) {
        totalElement.textContent = total;
    }

    if (errorElement) {
        errorElement.textContent = errors;
    }

    if (warningElement) {
        warningElement.textContent = warnings;
    }

    if (infoElement) {
        infoElement.textContent = info;
    }
}


// ────────────────────────────────────────────────────────────
// APPLY FILTERS
// ────────────────────────────────────────────────────────────

function applyFilters(resetPage = true) {

    const searchTerm =
        (
            document.getElementById(
                'searchInput'
            )?.value || ''
        )
        .trim()
        .toLowerCase();


    const levelFilter =
        document.getElementById(
            'levelFilter'
        )?.value || 'ALL';


    const typeFilter =
        document.getElementById(
            'typeFilter'
        )?.value || 'ALL';


    const agentFilter =
        document.getElementById(
            'agentFilter'
        )?.value || 'ALL';


    filteredLogs =
        allLogs.filter(log => {

            const message =
                String(
                    log.message || ''
                ).toLowerCase();

            const agent =
                String(
                    log.agent_id || ''
                ).toLowerCase();

            const source =
                String(
                    log.source || ''
                ).toLowerCase();

            const type =
                String(
                    log.log_type || ''
                ).toLowerCase();

            const level =
                String(
                    log.level || 'INFO'
                ).toUpperCase();


            const matchesSearch =
                !searchTerm ||
                message.includes(searchTerm) ||
                agent.includes(searchTerm) ||
                source.includes(searchTerm) ||
                type.includes(searchTerm);


            const matchesLevel =
                levelFilter === 'ALL' ||
                level === levelFilter;


            const matchesType =
                typeFilter === 'ALL' ||
                log.log_type === typeFilter;


            const matchesAgent =
                agentFilter === 'ALL' ||
                log.agent_id === agentFilter;


            return (
                matchesSearch &&
                matchesLevel &&
                matchesType &&
                matchesAgent
            );
        });


    if (resetPage) {
        currentPage = 1;
    }

    renderLogs();

    updatePagination();
}


// ────────────────────────────────────────────────────────────
// SEARCH
// ────────────────────────────────────────────────────────────

function searchLogs() {
    applyFilters(true);
}


// ────────────────────────────────────────────────────────────
// RESET FILTERS
// ────────────────────────────────────────────────────────────

function resetFilters() {

    const search =
        document.getElementById(
            'searchInput'
        );

    const level =
        document.getElementById(
            'levelFilter'
        );

    const type =
        document.getElementById(
            'typeFilter'
        );

    const agent =
        document.getElementById(
            'agentFilter'
        );


    if (search) {
        search.value = '';
    }

    if (level) {
        level.value = 'ALL';
    }

    if (type) {
        type.value = 'ALL';
    }

    if (agent) {
        agent.value = 'ALL';
    }


    currentPage = 1;

    filteredLogs =
        [...allLogs];

    renderLogs();

    updatePagination();
}


// ────────────────────────────────────────────────────────────
// RENDER LOGS
// ────────────────────────────────────────────────────────────

function renderLogs() {

    const tbody =
        document.getElementById(
            'logsBody'
        );

    if (!tbody) return;


    const start =
        (currentPage - 1) * pageSize;

    const end =
        start + pageSize;

    const pageData =
        filteredLogs.slice(
            start,
            end
        );


    if (pageData.length === 0) {

        tbody.innerHTML = `
            <tr>
                <td colspan="7">

                    <div class="empty-state">

                        <i
                            class="fas fa-inbox"
                            style="font-size:2rem;opacity:.5;"
                        ></i>

                        <h3>No logs found</h3>

                        <p>
                            No real logs match your
                            current filters.
                        </p>

                    </div>

                </td>
            </tr>
        `;

        return;
    }


    tbody.innerHTML =
        pageData.map(log => {

            const level =
                String(
                    log.level || 'INFO'
                ).toUpperCase();

            const levelClass =
                getLevelClass(level);


            const message =
                String(
                    log.message || ''
                );


            const shortMessage =
                message.length > 150
                    ? `${message.substring(0, 150)}...`
                    : message;


            return `
                <tr>

                    <td
                        title="${escapeHtml(
                            formatLogDate(
                                log.timestamp
                            )
                        )}"
                    >
                        ${escapeHtml(
                            formatTimeAgo(
                                log.timestamp
                            )
                        )}
                    </td>


                    <td>
                        <span
                            style="
                                color:var(--blue);
                                font-family:monospace;
                            "
                        >
                            ${escapeHtml(
                                log.agent_id || '-'
                            )}
                        </span>
                    </td>


                    <td>
                        ${escapeHtml(
                            log.source || '-'
                        )}
                    </td>


                    <td>
                        <span
                            class="badge badge-INFO"
                        >
                            ${escapeHtml(
                                log.log_type || '-'
                            )}
                        </span>
                    </td>


                    <td>
                        <span
                            class="badge badge-${levelClass}"
                        >
                            ${escapeHtml(level)}
                        </span>
                    </td>


                    <td
                        title="${escapeHtml(message)}"
                        style="
                            max-width:400px;
                            overflow:hidden;
                            text-overflow:ellipsis;
                            white-space:nowrap;
                            font-family:monospace;
                            font-size:.75rem;
                        "
                    >
                        ${escapeHtml(
                            shortMessage
                        )}
                    </td>


                    <td>
                        ${escapeHtml(
                            log.os || '-'
                        )}
                    </td>

                </tr>
            `;

        }).join('');
}


// ────────────────────────────────────────────────────────────
// PAGINATION
// ────────────────────────────────────────────────────────────

function updatePagination() {

    const totalPages =
        Math.ceil(
            filteredLogs.length /
            pageSize
        ) || 1;


    const pageInfo =
        document.getElementById(
            'pageInfo'
        );

    const prevButton =
        document.getElementById(
            'prevPage'
        );

    const nextButton =
        document.getElementById(
            'nextPage'
        );

    const totalResults =
        document.getElementById(
            'totalResults'
        );


    if (pageInfo) {

        pageInfo.textContent =
            `Page ${currentPage} of ${totalPages}`;
    }


    if (prevButton) {

        prevButton.disabled =
            currentPage <= 1;
    }


    if (nextButton) {

        nextButton.disabled =
            currentPage >= totalPages;
    }


    if (totalResults) {

        totalResults.textContent =
            `${filteredLogs.length} logs`;
    }
}


// ────────────────────────────────────────────────────────────
// CHANGE PAGE
// ────────────────────────────────────────────────────────────

function changePage(delta) {

    const totalPages =
        Math.ceil(
            filteredLogs.length /
            pageSize
        ) || 1;


    const newPage =
        currentPage + delta;


    if (
        newPage < 1 ||
        newPage > totalPages
    ) {
        return;
    }


    currentPage =
        newPage;


    renderLogs();

    updatePagination();


    const container =
        document.querySelector(
            '.table-container'
        );


    if (container) {

        container.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}


// ────────────────────────────────────────────────────────────
// FILTER BY LEVEL
// ────────────────────────────────────────────────────────────

function filterByLevel(level) {

    const select =
        document.getElementById(
            'levelFilter'
        );

    if (select) {
        select.value = level || 'ALL';
    }

    applyFilters(true);
}


// ────────────────────────────────────────────────────────────
// CSV ESCAPE
// ────────────────────────────────────────────────────────────

function csvEscape(value) {

    const text =
        value === null ||
        value === undefined
            ? ''
            : String(value);

    return `"${text.replace(
        /"/g,
        '""'
    )}"`;
}


// ────────────────────────────────────────────────────────────
// EXPORT CSV
// ────────────────────────────────────────────────────────────

function exportLogsCSV() {

    if (filteredLogs.length === 0) {

        alert(
            'No real logs available to export.'
        );

        return;
    }


    const headers = [
        'ID',
        'Timestamp',
        'Agent',
        'Source',
        'Type',
        'Level',
        'Message',
        'OS'
    ];


    const rows =
        filteredLogs.map(log => [

            log.id || '',

            log.timestamp || '',

            log.agent_id || '',

            log.source || '',

            log.log_type || '',

            log.level || '',

            log.message || '',

            log.os || ''

        ]);


    const csvRows = [

        headers.map(csvEscape).join(','),

        ...rows.map(
            row =>
                row
                    .map(csvEscape)
                    .join(',')
        )

    ];


    const blob =
        new Blob(
            [
                csvRows.join('\n')
            ],
            {
                type:
                    'text/csv;charset=utf-8;'
            }
        );


    const url =
        URL.createObjectURL(blob);


    const link =
        document.createElement('a');


    link.href = url;


    link.download =
        `siem_logs_${
            new Date()
                .toISOString()
                .substring(0, 10)
        }.csv`;


    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);
}


// ────────────────────────────────────────────────────────────
// UPDATE LAST UPDATE
// ────────────────────────────────────────────────────────────

function updateLastUpdate() {

    const now =
        new Date()
            .toLocaleTimeString();


    const lastUpdate =
        document.getElementById(
            'lastUpdate'
        );


    if (lastUpdate) {

        lastUpdate.textContent =
            `Last update: ${now}`;
    }


    const statusBar =
        document.getElementById(
            'statusBarRight'
        );


    if (statusBar) {

        statusBar.textContent =
            `Last scan: ${now}`;
    }
}


// ────────────────────────────────────────────────────────────
// EVENT LISTENERS
// ────────────────────────────────────────────────────────────

document.addEventListener(
    'DOMContentLoaded',
    function () {

        const search =
            document.getElementById(
                'searchInput'
            );


        const level =
            document.getElementById(
                'levelFilter'
            );


        const type =
            document.getElementById(
                'typeFilter'
            );


        const agent =
            document.getElementById(
                'agentFilter'
            );


        const prev =
            document.getElementById(
                'prevPage'
            );


        const next =
            document.getElementById(
                'nextPage'
            );


        const reset =
            document.getElementById(
                'resetFilters'
            );


        const exportButton =
            document.getElementById(
                'exportCSV'
            );


        if (search) {

            search.addEventListener(
                'input',
                searchLogs
            );
        }


        if (level) {

            level.addEventListener(
                'change',
                searchLogs
            );
        }


        if (type) {

            type.addEventListener(
                'change',
                searchLogs
            );
        }


        if (agent) {

            agent.addEventListener(
                'change',
                searchLogs
            );
        }


        if (prev) {

            prev.addEventListener(
                'click',
                () => changePage(-1)
            );
        }


        if (next) {

            next.addEventListener(
                'click',
                () => changePage(1)
            );
        }


        if (reset) {

            reset.addEventListener(
                'click',
                resetFilters
            );
        }


        if (exportButton) {

            exportButton.addEventListener(
                'click',
                exportLogsCSV
            );
        }


        loadLogs();
    }
);


// ────────────────────────────────────────────────────────────
// AUTO REFRESH
// ────────────────────────────────────────────────────────────

setInterval(
    () => loadLogs({ silent: true }),
    15000
);


// ────────────────────────────────────────────────────────────
// GLOBAL ACCESS
// ────────────────────────────────────────────────────────────

window.SiemLogs = {

    loadLogs,

    searchLogs,

    resetFilters,

    changePage,

    exportLogsCSV,

    filterByLevel

};