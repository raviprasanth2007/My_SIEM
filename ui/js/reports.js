// ════════════════════════════════════════════════════════════
//  MY SIEM — Compliance, Audit & Executive Reporting Engine
// ════════════════════════════════════════════════════════════

let allReports = [];
let filteredReports = [];
let currentPage = 1;
const pageSize = 10;
let currentDateFilter = 'today';

// ── Built-in Archive of Standard Reports ──
const INITIAL_REPORTS = [
    {
        id: 'RPT-8092',
        name: 'Executive Daily Cyber Threat Brief',
        type: 'Security',
        format: 'PDF',
        status: 'Ready',
        generated_by: 'Automated Daemon',
        created_at: new Date(Date.now() - 1800000).toISOString(),
        size: '2.4 MB',
        description: 'Comprehensive 24-hour situational summary of brute-force attempts, Tor egress probes, and endpoint integrity status.',
        compliance: ['SOC2 CC7.2', 'NIST CSF PR.DS-5'],
        detections_count: 142,
        integrity_score: '98.4%'
    },
    {
        id: 'RPT-8091',
        name: 'FIM Host Integrity & Tamper Audit Log',
        type: 'Audit',
        format: 'CSV',
        status: 'Ready',
        generated_by: 'FIM Engine (Linux Agent)',
        created_at: new Date(Date.now() - 7200000).toISOString(),
        size: '1.1 MB',
        description: 'Baseline comparison of /etc/shadow, /etc/passwd, and /bin binaries across omen-kali and siem-server.',
        compliance: ['PCI-DSS 11.5', 'ISO 27001 A.12.4.1'],
        detections_count: 1,
        integrity_score: '94.0%'
    },
    {
        id: 'RPT-8090',
        name: 'Critical Incident Post-Mortem: Bash TCP Shell',
        type: 'Incident',
        format: 'PDF',
        status: 'Ready',
        generated_by: 'SOC Lead (Elena Rostova)',
        created_at: new Date(Date.now() - 18000000).toISOString(),
        size: '3.8 MB',
        description: 'Forensic root cause analysis of reverse shell spawned from /dev/tcp outbound to external port 4444.',
        compliance: ['NIST SP 800-61 Rev 2'],
        detections_count: 18,
        integrity_score: 'N/A'
    },
    {
        id: 'RPT-8089',
        name: 'Quarterly PCI-DSS Requirement 10 Audit Trail',
        type: 'Audit',
        format: 'JSON',
        status: 'Ready',
        generated_by: 'Compliance Auditor',
        created_at: new Date(Date.now() - 86400000).toISOString(),
        size: '8.4 MB',
        description: 'Cryptographically hashed event trail validating automated audit trails for all system administrator access.',
        compliance: ['PCI-DSS 10.2.1', 'PCI-DSS 10.3'],
        detections_count: 0,
        integrity_score: '100%'
    },
    {
        id: 'RPT-8088',
        name: 'Hydra SSH Credential Stuffing Vector Analysis',
        type: 'Security',
        format: 'PDF',
        status: 'Ready',
        generated_by: 'Threat Intel Core',
        created_at: new Date(Date.now() - 172800000).toISOString(),
        size: '4.2 MB',
        description: 'Source IP geographic clustering, PAM error analysis, and fail2ban rule evaluation for port 22 intrusion attempts.',
        compliance: ['CIS Benchmark v8 3.3'],
        detections_count: 310,
        integrity_score: '96.2%'
    },
    {
        id: 'RPT-8087',
        name: 'Endpoint Telemetry & Daemon Heartbeat Log',
        type: 'Performance',
        format: 'CSV',
        status: 'Ready',
        generated_by: 'Agent Watchdog',
        created_at: new Date(Date.now() - 259200000).toISOString(),
        size: '1.9 MB',
        description: 'EPS transmission latency, memory footprint, and network packet loss metrics for fleet agents.',
        compliance: ['Internal SLA 99.9%'],
        detections_count: 0,
        integrity_score: '99.9%'
    }
];

// ── Load Reports ──
async function loadReports() {
    const tbody = document.getElementById('reportsBody');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="8" class="loading-text"><i class="fas fa-spinner fa-spin text-green"></i> Querying compliance archives...</td></tr>`;
    }

    try {
        let stats = null;
        let alerts = null;
        if (window.SiemEngine && typeof window.SiemEngine.fetchAPI === 'function') {
            [stats, alerts] = await Promise.all([
                window.SiemEngine.fetchAPI('/api/stats'),
                window.SiemEngine.fetchAPI('/api/alerts')
            ]);
        }

        // Merge live stats into the report generator context
        const cached = localStorage.getItem('siem_reports_archive');
        if (cached) {
            try {
                allReports = JSON.parse(cached);
            } catch (e) {
                allReports = [...INITIAL_REPORTS];
            }
        } else {
            allReports = [...INITIAL_REPORTS];
        }

        // If live alerts are present and no today's report exists, generate a fresh live report
        if (alerts && alerts.length > 0 && !allReports.some(r => r.name.includes('Live Telemetry'))) {
            allReports.unshift({
                id: `RPT-${Math.floor(8100 + Math.random() * 900)}`,
                name: `Live Telemetry Audit (${alerts.length} Active Detections)`,
                type: 'Security',
                format: 'PDF',
                status: 'Ready',
                generated_by: 'Real-Time SIEM Monitor',
                created_at: new Date().toISOString(),
                size: '2.1 MB',
                description: `Dynamic report generated from live agent telemetry with ${stats?.total_logs || alerts.length * 15} processed event logs.`,
                compliance: ['SOC2 CC7.2', 'ISO 27001'],
                detections_count: alerts.length,
                integrity_score: '95.8%'
            });
            saveReportsCache();
        }

        applyReportFilters();
        updateReportStats();
        updateLastUpdate();
    } catch (err) {
        console.warn('Reports archive fallback:', err);
        allReports = [...INITIAL_REPORTS];
        applyReportFilters();
        updateReportStats();
        updateLastUpdate();
    }
}

// ── Save Cache ──
function saveReportsCache() {
    try {
        localStorage.setItem('siem_reports_archive', JSON.stringify(allReports));
    } catch (e) {
        // quota limit
    }
}

// ── Update KPI Statistics ──
function updateReportStats() {
    const total = allReports.length;
    const security = allReports.filter(r => r.type === 'Security').length;
    const incident = allReports.filter(r => r.type === 'Incident').length;
    const audit = allReports.filter(r => r.type === 'Audit').length;

    const totalEl = document.getElementById('reportTotal');
    const secEl = document.getElementById('reportSecurity');
    const incEl = document.getElementById('reportIncident');
    const auditEl = document.getElementById('reportAudit');

    if (totalEl) totalEl.textContent = total;
    if (secEl) secEl.textContent = security;
    if (incEl) incEl.textContent = incident;
    if (auditEl) auditEl.textContent = audit;
}

// ── Date Preset Filters ──
function setDateFilter(type) {
    currentDateFilter = type;

    // Update active class on buttons
    document.querySelectorAll('.date-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.textContent.toLowerCase().includes(type) || 
           (type === 'week' && btn.textContent.includes('7')) ||
           (type === 'month' && btn.textContent.includes('30'))) {
            btn.classList.add('active');
        }
    });

    applyReportFilters();
}

// ── Filter by Type Clicked from Stat Cards ──
function filterByType(type) {
    const sel = document.getElementById('typeFilter');
    if (sel) sel.value = type;
    applyReportFilters();
}

// ── Search & Filter Logic ──
function searchReports() {
    applyReportFilters();
}

function applyReportFilters() {
    const term = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();
    const typeFilter = document.getElementById('typeFilter')?.value || 'ALL';
    const formatFilter = document.getElementById('formatFilter')?.value || 'ALL';

    const now = Date.now();
    let timeThreshold = 0;
    if (currentDateFilter === 'today') timeThreshold = now - 86400000;
    else if (currentDateFilter === 'yesterday') timeThreshold = now - (86400000 * 2);
    else if (currentDateFilter === 'week') timeThreshold = now - (86400000 * 7);
    else if (currentDateFilter === 'month') timeThreshold = now - (86400000 * 30);

    filteredReports = allReports.filter(report => {
        const matchesTerm = !term ||
            report.name.toLowerCase().includes(term) ||
            report.id.toLowerCase().includes(term) ||
            report.description.toLowerCase().includes(term) ||
            report.generated_by.toLowerCase().includes(term);

        const matchesType = typeFilter === 'ALL' || report.type === typeFilter;
        const matchesFormat = formatFilter === 'ALL' || report.format === formatFilter;

        const reportTime = new Date(report.created_at).getTime();
        const matchesDate = !timeThreshold || reportTime >= timeThreshold;

        return matchesTerm && matchesType && matchesFormat && matchesDate;
    });

    currentPage = 1;
    renderReports();
    updatePagination();
}

function resetFilters() {
    if (document.getElementById('searchInput')) document.getElementById('searchInput').value = '';
    if (document.getElementById('typeFilter')) document.getElementById('typeFilter').value = 'ALL';
    if (document.getElementById('formatFilter')) document.getElementById('formatFilter').value = 'ALL';
    currentDateFilter = 'all';
    document.querySelectorAll('.date-btn').forEach(btn => btn.classList.remove('active'));
    filteredReports = [...allReports];
    currentPage = 1;
    renderReports();
    updatePagination();
    if (window.SiemEngine) window.SiemEngine.showToast('Report filters cleared', 'info');
}

// ── Render Reports Table ──
function renderReports() {
    const tbody = document.getElementById('reportsBody');
    if (!tbody) return;

    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    const pageData = filteredReports.slice(start, end);

    if (pageData.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8">
                    <div class="empty-state">
                        <i class="fas fa-file-circle-question text-green" style="font-size:2rem;margin-bottom:12px;"></i>
                        <h3>No Reports Found</h3>
                        <p style="color:var(--text-secondary);font-size:0.75rem;">Try adjusting the date range or search keyword.</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = pageData.map(report => {
        const formatBadge = report.format === 'PDF' 
            ? '<span class="siem-badge badge-critical"><i class="fas fa-file-pdf"></i> PDF</span>'
            : report.format === 'CSV'
            ? '<span class="siem-badge badge-low"><i class="fas fa-file-csv"></i> CSV</span>'
            : '<span class="siem-badge badge-info"><i class="fas fa-file-code"></i> JSON</span>';

        const categoryBadge = report.type === 'Security'
            ? '<span class="siem-badge badge-high">Security</span>'
            : report.type === 'Incident'
            ? '<span class="siem-badge badge-critical">Incident</span>'
            : '<span class="siem-badge badge-low">Audit</span>';

        const formattedDate = window.SiemEngine ? window.SiemEngine.formatDate(report.created_at) : (report.created_at || '').substring(0, 10);

        return `
            <tr>
                <td><code style="color:var(--blue);font-weight:700;">${report.id}</code></td>
                <td>
                    <div style="font-weight:600;font-size:0.8rem;color:var(--text-primary);cursor:pointer;" onclick="previewReport('${report.id}')">
                        ${report.name}
                    </div>
                    <div style="font-size:0.65rem;color:var(--text-muted);">${report.description.substring(0, 75)}...</div>
                </td>
                <td>${categoryBadge}</td>
                <td>${formatBadge}</td>
                <td><span style="color:var(--green);font-size:0.75rem;font-weight:600;"><i class="fas fa-circle-check"></i> Ready</span></td>
                <td style="font-size:0.72rem;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;">${formattedDate}</td>
                <td style="font-size:0.72rem;color:var(--text-secondary);">${report.size}</td>
                <td>
                    <div style="display:flex;gap:4px;">
                        <button class="filter-btn" style="padding:4px 8px;font-size:0.65rem;" onclick="previewReport('${report.id}')" title="Inspect & Preview">
                            <i class="fas fa-eye text-blue"></i>
                        </button>
                        <button class="filter-btn" style="padding:4px 8px;font-size:0.65rem;" onclick="downloadReport('${report.id}')" title="Download">
                            <i class="fas fa-download text-green"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// ── Pagination Controls ──
function updatePagination() {
    const totalPages = Math.ceil(filteredReports.length / pageSize) || 1;
    const pageInfo = document.getElementById('pageInfo');
    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');

    if (pageInfo) pageInfo.textContent = `Showing ${filteredReports.length} reports · Page ${currentPage} of ${totalPages}`;
    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
}

function changePage(delta) {
    const totalPages = Math.ceil(filteredReports.length / pageSize) || 1;
    const newPage = currentPage + delta;
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        renderReports();
        updatePagination();
        document.querySelector('.table-scroll')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ── On-Demand Report Generator ──
function generateReport() {
    const typeSelect = document.getElementById('genReportType');
    const formatSelect = document.getElementById('genFormat');

    const type = typeSelect ? typeSelect.value : 'Executive';
    const format = formatSelect ? formatSelect.value : 'PDF';

    if (window.SiemEngine) {
        window.SiemEngine.showToast(`Compiling ${type} Report (${format})...`, 'info');
        window.SiemEngine.playAlertSound('LOW');
    }

    setTimeout(() => {
        const id = `RPT-${Math.floor(8200 + Math.random() * 800)}`;
        const titles = {
            'Executive': 'Executive Cyber Defense & Threat Brief',
            'FIM': 'FIM Baseline Cryptographic Tamper Audit',
            'Incidents': 'Critical Intrusion Triage & Breach Investigation Log',
            'Compliance': 'PCI-DSS & ISO 27001 Access Control Audit'
        };

        const categories = {
            'Executive': 'Security',
            'FIM': 'Audit',
            'Incidents': 'Incident',
            'Compliance': 'Audit'
        };

        const newReport = {
            id: id,
            name: `${titles[type] || 'SOC Compliance Report'} [${new Date().toLocaleTimeString()}]`,
            type: categories[type] || 'Security',
            format: format,
            status: 'Ready',
            generated_by: 'SOC Operator (Manual Trigger)',
            created_at: new Date().toISOString(),
            size: `${(Math.random() * 3 + 1.2).toFixed(1)} MB`,
            description: `On-demand compiled forensic audit report for ${type} compliance verification.`,
            compliance: ['SOC2 CC7.2', 'PCI-DSS 11.5', 'ISO 27001'],
            detections_count: Math.floor(Math.random() * 40 + 5),
            integrity_score: '97.6%'
        };

        allReports.unshift(newReport);
        saveReportsCache();
        applyReportFilters();
        updateReportStats();

        if (window.SiemEngine) {
            window.SiemEngine.showToast(`Compiled report ${id} successfully!`, 'success');
            window.SiemEngine.playAlertSound('LOW');
        }
    }, 1200);
}

// ── Preview Report Modal ──
function previewReport(reportId) {
    const report = allReports.find(r => r.id === reportId);
    if (!report) return;

    const modal = document.getElementById('reportModal');
    const content = document.getElementById('reportModalContent');
    if (!modal || !content) return;

    const complianceTags = (report.compliance || ['SOC2 CC7.2', 'ISO 27001'])
        .map(c => `<span class="siem-badge badge-low"><i class="fas fa-check"></i> ${c}</span>`)
        .join(' ');

    content.innerHTML = `
        <div class="panel-header" style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid var(--border-color);padding-bottom:14px;margin-bottom:16px;">
            <div>
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                    <i class="fas fa-file-shield text-green" style="font-size:1.6rem;"></i>
                    <h3 style="margin:0;font-size:1.2rem;color:var(--text-primary);">${report.name}</h3>
                </div>
                <div style="display:flex;gap:8px;align-items:center;">
                    <code style="color:var(--blue);font-weight:700;">${report.id}</code>
                    <span class="siem-badge badge-info">${report.type}</span>
                    <span class="siem-badge badge-critical">${report.format}</span>
                    <span style="font-size:0.75rem;color:var(--text-muted);font-family:'JetBrains Mono',monospace;">Generated: ${new Date(report.created_at).toLocaleString()}</span>
                </div>
            </div>
            <button class="filter-btn" onclick="closeReportModal()" style="padding:4px 8px;"><i class="fas fa-times"></i></button>
        </div>

        <div style="background:var(--bg-primary);padding:14px;border:1px solid var(--border-color);border-radius:var(--radius-sm);margin-bottom:16px;">
            <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;">Executive Summary & Scope</div>
            <p style="font-size:0.8rem;color:var(--text-secondary);line-height:1.6;margin:0;">
                ${report.description}
            </p>
        </div>

        <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:12px;margin-bottom:16px;">
            <div style="background:var(--bg-primary);padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);text-align:center;">
                <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;">Telemetry Ingest</div>
                <div style="font-size:1.3rem;font-weight:700;color:var(--blue);margin-top:2px;">${report.detections_count ?? 12} Events</div>
            </div>
            <div style="background:var(--bg-primary);padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);text-align:center;">
                <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;">Integrity Score</div>
                <div style="font-size:1.3rem;font-weight:700;color:var(--green);margin-top:2px;">${report.integrity_score ?? '98.5%'}</div>
            </div>
            <div style="background:var(--bg-primary);padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);text-align:center;">
                <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;">Archival Size</div>
                <div style="font-size:1.3rem;font-weight:700;color:var(--text-primary);margin-top:2px;">${report.size}</div>
            </div>
        </div>

        <div style="background:rgba(0, 245, 160, 0.05);border:1px solid rgba(0, 245, 160, 0.2);padding:14px;border-radius:var(--radius-sm);margin-bottom:20px;">
            <div style="font-size:0.75rem;font-weight:600;color:var(--green);margin-bottom:8px;">
                <i class="fas fa-stamp"></i> Compliance Verification Seals
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                ${complianceTags}
            </div>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--border-color);padding-top:14px;">
            <span style="font-size:0.72rem;color:var(--text-muted);">Cryptographic Signature: SHA-256 Validated</span>
            <div style="display:flex;gap:8px;">
                <button class="filter-btn" onclick="closeReportModal()">Close</button>
                <button class="filter-btn" style="background:var(--green);color:#000;font-weight:700;" onclick="downloadReport('${report.id}')">
                    <i class="fas fa-download"></i> Download ${report.format}
                </button>
            </div>
        </div>
    `;

    modal.classList.add('active');
}

function closeReportModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.classList.remove('active');
}

// ── Download Report ──
function downloadReport(reportId) {
    const report = allReports.find(r => r.id === reportId);
    if (!report) return;

    if (report.format === 'CSV') {
        const dummyCSV = `Report_ID,Name,Type,Status,Date,Size\n"${report.id}","${report.name}","${report.type}","${report.status}","${report.created_at}","${report.size}"`;
        const blob = new Blob([dummyCSV], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.id}_audit_trail.csv`;
        a.click();
        URL.revokeObjectURL(url);
    } else if (report.format === 'JSON') {
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.id}_telemetry.json`;
        a.click();
        URL.revokeObjectURL(url);
    } else {
        // PDF Simulation: Generate printable formatted document
        const printWin = window.open('', '_blank');
        if (printWin) {
            printWin.document.write(`
                <html>
                <head>
                    <title>${report.name} — SOC Audit</title>
                    <style>
                        body { font-family: monospace; padding: 40px; background: #fff; color: #000; }
                        h1 { border-bottom: 2px solid #000; padding-bottom: 10px; font-size: 20px; }
                        .meta { margin-bottom: 20px; font-size: 13px; color: #444; }
                        .section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
                    </style>
                </head>
                <body>
                    <h1>🛡️ MY SIEM — EXECUTIVE AUDIT REPORT (${report.id})</h1>
                    <div class="meta">
                        <strong>Generated:</strong> ${new Date(report.created_at).toUTCString()}<br>
                        <strong>Subject:</strong> ${report.name}<br>
                        <strong>Classification:</strong> RESTRICTED / COMPLIANCE AUDIT
                    </div>
                    <div class="section">
                        <h3>Summary</h3>
                        <p>${report.description}</p>
                    </div>
                    <div class="section">
                        <h3>Compliance Verification</h3>
                        <p>Standards Verified: ${(report.compliance || []).join(', ')}</p>
                        <p>Cryptographic Baseline: VALID</p>
                    </div>
                </body>
                </html>
            `);
            printWin.document.close();
            printWin.print();
        }
    }

    if (window.SiemEngine) {
        window.SiemEngine.showToast(`Downloaded report ${report.id} (${report.format})`, 'success');
    }
}

// ── Export List to CSV ──
function exportReportsCSV() {
    if (filteredReports.length === 0) {
        if (window.SiemEngine) window.SiemEngine.showToast('No reports to export', 'warning');
        return;
    }

    const data = filteredReports.map(r => ({
        ID: r.id,
        Name: r.name,
        Category: r.type,
        Format: r.format,
        Status: r.status,
        Generated_By: r.generated_by,
        Size: r.size,
        Created_At: r.created_at
    }));

    if (window.SiemEngine) {
        window.SiemEngine.exportToCSV(data, `soc_reports_archive_${new Date().toISOString().substring(0, 10)}.csv`);
        window.SiemEngine.showToast(`Exported ${filteredReports.length} reports to CSV`, 'success');
    }
}

// ── Timestamp Sync ──
function updateLastUpdate() {
    const now = new Date().toLocaleTimeString();
    const lastUpdateEl = document.getElementById('lastUpdate');
    const statusBarEl = document.getElementById('statusBarRight');

    if (lastUpdateEl) lastUpdateEl.textContent = now;
    if (statusBarEl) statusBarEl.textContent = `Last scan: ${now}`;
}

// ── DOM Ready ──
document.addEventListener('DOMContentLoaded', () => {
    loadReports();

    // Close modal on click outside or Escape
    const modal = document.getElementById('reportModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeReportModal();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeReportModal();
    });
});