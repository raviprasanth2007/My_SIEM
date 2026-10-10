// ════════════════════════════════════════════════════════════
//  MY SIEM — Users & Access Control Engine
// ════════════════════════════════════════════════════════════

let allUsers = [];
let filteredUsers = [];
let currentPage = 1;
const pageSize = 10;

// ── Default Mock Users Directory ──
const MOCK_USERS = [
    {
        id: 'USR-0001',
        full_name: 'Administrator (SecOps Lead)',
        username: 'admin.soc',
        email: 'admin@siem.local',
        role: 'Admin',
        status: 'Active',
        mfa_enabled: true,
        last_login: new Date(Date.now() - 300000).toISOString(),
        created_at: '2026-01-01T00:00:00Z',
        sessions: 2,
        ip_address: '100.90.174.77 (Tailscale)'
    },
    {
        id: 'USR-0002',
        full_name: 'Kali Hunter (PenTester)',
        username: 'omen.kali',
        email: 'kali@siem.local',
        role: 'Threat Hunter',
        status: 'Active',
        mfa_enabled: true,
        last_login: new Date(Date.now() - 1200000).toISOString(),
        created_at: '2026-02-15T08:30:00Z',
        sessions: 1,
        ip_address: '100.100.80.25 (Tailscale)'
    },
    {
        id: 'USR-0003',
        full_name: 'Elena Rostova',
        username: 'elena.rostova',
        email: 'elena.r@soc.enterprise',
        role: 'SOC Lead',
        status: 'Active',
        mfa_enabled: true,
        last_login: new Date(Date.now() - 3600000).toISOString(),
        created_at: '2026-02-01T10:15:00Z',
        sessions: 1,
        ip_address: '192.168.1.102'
    },
    {
        id: 'USR-0004',
        full_name: 'Marcus Brody',
        username: 'marcus.brody',
        email: 'm.brody@soc.enterprise',
        role: 'Incident Responder',
        status: 'Active',
        mfa_enabled: true,
        last_login: new Date(Date.now() - 7200000).toISOString(),
        created_at: '2026-03-10T12:00:00Z',
        sessions: 3,
        ip_address: '192.168.1.105'
    },
    {
        id: 'USR-0005',
        full_name: 'Sarah Chen',
        username: 'sarah.chen',
        email: 's.chen@soc.enterprise',
        role: 'Security Analyst',
        status: 'Active',
        mfa_enabled: false,
        last_login: new Date(Date.now() - 14400000).toISOString(),
        created_at: '2026-03-22T09:00:00Z',
        sessions: 1,
        ip_address: '192.168.1.114'
    },
    {
        id: 'USR-0006',
        full_name: 'Devin Thorne',
        username: 'devin.thorne',
        email: 'd.thorne@soc.enterprise',
        role: 'Compliance Auditor',
        status: 'Active',
        mfa_enabled: true,
        last_login: new Date(Date.now() - 86400000).toISOString(),
        created_at: '2026-04-05T14:20:00Z',
        sessions: 0,
        ip_address: '192.168.1.120'
    },
    {
        id: 'USR-0007',
        full_name: 'Vikram Patel',
        username: 'vikram.patel',
        email: 'v.patel@soc.enterprise',
        role: 'Security Analyst',
        status: 'Suspended',
        mfa_enabled: false,
        last_login: new Date(Date.now() - 259200000).toISOString(),
        created_at: '2026-04-18T11:45:00Z',
        sessions: 0,
        ip_address: '10.0.4.15'
    },
    {
        id: 'USR-0008',
        full_name: 'Zorin Node Daemon',
        username: 'zorin.agent',
        email: 'agent-zorin@siem.local',
        role: 'Security Analyst',
        status: 'Inactive',
        mfa_enabled: true,
        last_login: new Date(Date.now() - 604800000).toISOString(),
        created_at: '2026-05-01T07:10:00Z',
        sessions: 0,
        ip_address: '100.115.92.14'
    }
];

// ── Initialize and Load Users ──
async function loadUsers() {
    const tbody = document.getElementById('usersBody');
    const refreshIcon = document.getElementById('refreshIcon');
    if (refreshIcon) refreshIcon.classList.add('fa-spin');

    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="8" class="loading-text"><i class="fas fa-spinner fa-spin text-green"></i> Loading analyst directory...</td></tr>`;
    }

    try {
        // Attempt live API fetch via SiemEngine
        let agents = null;
        if (window.SiemEngine && typeof window.SiemEngine.fetchAPI === 'function') {
            agents = await window.SiemEngine.fetchAPI('/api/agents');
        }

        if (agents && Array.isArray(agents) && agents.length > 0) {
            // Map live agents into operator users
            const liveUsers = agents.map((agent, idx) => {
                const roles = ['SOC Lead', 'Threat Hunter', 'Security Analyst', 'Incident Responder'];
                return {
                    id: `USR-${String(idx + 1).padStart(4, '0')}`,
                    full_name: agent.hostname ? `${agent.hostname.toUpperCase()} Operator` : (agent.agent_id || `Agent ${idx + 1}`),
                    username: (agent.hostname || agent.agent_id || `user${idx + 1}`).toLowerCase().replace(/[^a-z0-9]/g, '.'),
                    email: `${(agent.hostname || agent.agent_id || `agent${idx + 1}`).toLowerCase()}@siem.local`,
                    role: idx === 0 ? 'Admin' : roles[idx % roles.length],
                    status: (agent.status === 'online' || agent.status === 'active') ? 'Active' : 'Inactive',
                    mfa_enabled: true,
                    last_login: agent.last_seen || new Date().toISOString(),
                    created_at: new Date(Date.now() - 30 * 86400000).toISOString(),
                    sessions: agent.status === 'online' ? 1 : 0,
                    ip_address: agent.ip_address || '100.90.174.77'
                };
            });

            // Merge with mock analysts to ensure a full SOC roster
            const existingIds = new Set(liveUsers.map(u => u.username));
            const extraUsers = MOCK_USERS.filter(u => !existingIds.has(u.username));
            allUsers = [...liveUsers, ...extraUsers];
        } else {
            // Use cached or default mock users
            const cached = localStorage.getItem('siem_users_cache');
            if (cached) {
                try {
                    allUsers = JSON.parse(cached);
                } catch(e) {
                    allUsers = [...MOCK_USERS];
                }
            } else {
                allUsers = [...MOCK_USERS];
            }
        }

        saveUsersCache();
        applyUserFilters();
        updateUserStats();
        updateLastUpdate();
    } catch (err) {
        console.warn('Fallback to local mock users directory:', err);
        allUsers = [...MOCK_USERS];
        applyUserFilters();
        updateUserStats();
        updateLastUpdate();
    } finally {
        if (refreshIcon) refreshIcon.classList.remove('fa-spin');
    }
}

// ── Save Cache ──
function saveUsersCache() {
    try {
        localStorage.setItem('siem_users_cache', JSON.stringify(allUsers));
    } catch(e) {
        // quota limit
    }
}

// ── Update KPI Statistics ──
function updateUserStats() {
    const total = allUsers.length;
    const active = allUsers.filter(u => u.status === 'Active').length;
    const suspended = allUsers.filter(u => u.status === 'Suspended' || u.status === 'Inactive').length;
    const admins = allUsers.filter(u => u.role === 'Admin').length;

    const totalEl = document.getElementById('userTotal');
    const activeEl = document.getElementById('userActive');
    const inactiveEl = document.getElementById('userInactive');
    const adminsEl = document.getElementById('userAdmins');

    if (totalEl) totalEl.textContent = total;
    if (activeEl) activeEl.textContent = active;
    if (inactiveEl) inactiveEl.textContent = suspended;
    if (adminsEl) adminsEl.textContent = admins;
}

// ── Role Color Helper ──
function getRoleBadge(role) {
    switch (role) {
        case 'Admin':
            return '<span class="siem-badge badge-critical"><i class="fas fa-shield-halved"></i> Admin</span>';
        case 'SOC Lead':
            return '<span class="siem-badge badge-high"><i class="fas fa-user-astronaut"></i> SOC Lead</span>';
        case 'Threat Hunter':
            return '<span class="siem-badge badge-medium"><i class="fas fa-crosshairs"></i> Hunter</span>';
        case 'Incident Responder':
            return '<span class="siem-badge badge-low"><i class="fas fa-fire-extinguisher"></i> Responder</span>';
        case 'Compliance Auditor':
            return '<span class="siem-badge badge-info"><i class="fas fa-clipboard-check"></i> Auditor</span>';
        default:
            return `<span class="siem-badge badge-info"><i class="fas fa-user-shield"></i> ${role}</span>`;
    }
}

// ── Status Badge Helper ──
function getStatusBadge(status) {
    switch (status) {
        case 'Active':
            return '<span style="color:var(--green);font-weight:600;font-size:0.75rem;"><span style="display:inline-block;width:7px;height:7px;background:var(--green);border-radius:50%;margin-right:5px;box-shadow:0 0 8px var(--green);"></span>Active</span>';
        case 'Suspended':
            return '<span style="color:var(--red);font-weight:600;font-size:0.75rem;"><span style="display:inline-block;width:7px;height:7px;background:var(--red);border-radius:50%;margin-right:5px;"></span>Suspended</span>';
        case 'Inactive':
        default:
            return '<span style="color:var(--text-muted);font-weight:600;font-size:0.75rem;"><span style="display:inline-block;width:7px;height:7px;background:var(--gray);border-radius:50%;margin-right:5px;"></span>Offline</span>';
    }
}

// ── Render Users Table ──
function renderUsers() {
    const tbody = document.getElementById('usersBody');
    if (!tbody) return;

    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    const pageData = filteredUsers.slice(start, end);

    if (pageData.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8">
                    <div class="empty-state">
                        <i class="fas fa-users-slash text-green" style="font-size:2rem;margin-bottom:12px;"></i>
                        <h3>No Analysts Found</h3>
                        <p style="color:var(--text-secondary);font-size:0.75rem;">Adjust search filters or click "Clear" to display all registered security operators.</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = pageData.map(user => {
        const initials = user.full_name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() || 'U';
        const formattedLastLogin = window.SiemEngine ? window.SiemEngine.formatTimeAgo(user.last_login) : user.last_login;
        
        const mfaBadge = user.mfa_enabled 
            ? '<span style="color:var(--green);font-size:0.72rem;font-weight:600;"><i class="fas fa-shield-check"></i> Enforced</span>'
            : '<span style="color:var(--yellow);font-size:0.72rem;font-weight:600;"><i class="fas fa-triangle-exclamation"></i> Pending</span>';

        return `
            <tr>
                <td>
                    <div class="user-meta-cell">
                        <div class="user-avatar-badge">${initials}</div>
                        <div>
                            <div class="user-meta-title">${user.full_name}</div>
                            <div class="user-meta-sub">${user.id} · ${user.ip_address || 'Local'}</div>
                        </div>
                    </div>
                </td>
                <td><code style="font-size:0.75rem;color:var(--blue);">${user.username}</code></td>
                <td style="font-size:0.75rem;color:var(--text-secondary);">${user.email}</td>
                <td>${getRoleBadge(user.role)}</td>
                <td>${getStatusBadge(user.status)}</td>
                <td>${mfaBadge}</td>
                <td style="font-size:0.72rem;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;">${formattedLastLogin}</td>
                <td>
                    <div style="display:flex;gap:4px;">
                        <button class="filter-btn" style="padding:4px 8px;font-size:0.65rem;" onclick="viewUserModal('${user.id}')" title="Inspect & Edit">
                            <i class="fas fa-sliders text-blue"></i>
                        </button>
                        <button class="filter-btn" style="padding:4px 8px;font-size:0.65rem;" onclick="toggleUserStatus('${user.id}')" title="Toggle Active/Suspended">
                            <i class="fas fa-power-off ${user.status === 'Active' ? 'text-green' : 'text-red'}"></i>
                        </button>
                        <button class="filter-btn" style="padding:4px 8px;font-size:0.65rem;" onclick="deleteUser('${user.id}')" title="Revoke User">
                            <i class="fas fa-trash text-red"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// ── Search & Filter Users ──
function searchUsers() {
    applyUserFilters();
}

function filterByRole(role) {
    const roleSelect = document.getElementById('roleFilter');
    if (roleSelect) roleSelect.value = role;
    applyUserFilters();
}

function filterByStatus(status) {
    const statusSelect = document.getElementById('statusFilter');
    if (statusSelect) statusSelect.value = status;
    applyUserFilters();
}

function applyUserFilters() {
    const search = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();
    const statusFilter = document.getElementById('statusFilter')?.value || 'ALL';
    const roleFilter = document.getElementById('roleFilter')?.value || 'ALL';
    const mfaFilter = document.getElementById('mfaFilter')?.value || 'ALL';

    filteredUsers = allUsers.filter(user => {
        const matchesSearch = !search ||
            (user.full_name || '').toLowerCase().includes(search) ||
            (user.username || '').toLowerCase().includes(search) ||
            (user.email || '').toLowerCase().includes(search) ||
            (user.id || '').toLowerCase().includes(search);

        const matchesStatus = statusFilter === 'ALL' || user.status === statusFilter;
        const matchesRole = roleFilter === 'ALL' || user.role === roleFilter;
        
        let matchesMFA = true;
        if (mfaFilter === 'enabled') matchesMFA = user.mfa_enabled === true;
        if (mfaFilter === 'disabled') matchesMFA = user.mfa_enabled === false;

        return matchesSearch && matchesStatus && matchesRole && matchesMFA;
    });

    currentPage = 1;
    renderUsers();
    updatePagination();
}

function resetFilters() {
    if (document.getElementById('searchInput')) document.getElementById('searchInput').value = '';
    if (document.getElementById('statusFilter')) document.getElementById('statusFilter').value = 'ALL';
    if (document.getElementById('roleFilter')) document.getElementById('roleFilter').value = 'ALL';
    if (document.getElementById('mfaFilter')) document.getElementById('mfaFilter').value = 'ALL';
    filteredUsers = [...allUsers];
    currentPage = 1;
    renderUsers();
    updatePagination();
    if (window.SiemEngine) window.SiemEngine.showToast('Filters cleared', 'info');
}

// ── Pagination Controls ──
function updatePagination() {
    const totalPages = Math.ceil(filteredUsers.length / pageSize) || 1;
    const pageInfo = document.getElementById('pageInfo');
    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');

    if (pageInfo) pageInfo.textContent = `Showing ${filteredUsers.length} analysts · Page ${currentPage} of ${totalPages}`;
    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
}

function changePage(delta) {
    const totalPages = Math.ceil(filteredUsers.length / pageSize) || 1;
    const newPage = currentPage + delta;
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        renderUsers();
        updatePagination();
        document.querySelector('.table-scroll')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ── Add User ──
function addUser() {
    const nameInput = document.getElementById('userName');
    const emailInput = document.getElementById('userEmail');
    const usernameInput = document.getElementById('userUsername');
    const roleInput = document.getElementById('userRole');
    const statusMsg = document.getElementById('addStatus');

    const fullName = nameInput ? nameInput.value.trim() : '';
    const email = emailInput ? emailInput.value.trim() : '';
    let username = usernameInput ? usernameInput.value.trim() : '';
    const role = roleInput ? roleInput.value : 'Security Analyst';

    if (!fullName || !email) {
        if (window.SiemEngine) window.SiemEngine.showToast('Full name and email are required', 'warning');
        return;
    }

    if (!username) {
        username = fullName.toLowerCase().replace(/[^a-z0-9]/g, '.');
    }

    // Check duplicate email
    if (allUsers.some(u => u.email.toLowerCase() === email.toLowerCase())) {
        if (window.SiemEngine) window.SiemEngine.showToast('An operator with this email already exists', 'error');
        return;
    }

    const newUser = {
        id: `USR-${String(allUsers.length + 1).padStart(4, '0')}`,
        full_name: fullName,
        username: username,
        email: email,
        role: role,
        status: 'Active',
        mfa_enabled: true,
        last_login: new Date().toISOString(),
        created_at: new Date().toISOString(),
        sessions: 1,
        ip_address: '127.0.0.1'
    };

    allUsers.unshift(newUser);
    saveUsersCache();
    applyUserFilters();
    updateUserStats();

    if (nameInput) nameInput.value = '';
    if (emailInput) emailInput.value = '';
    if (usernameInput) usernameInput.value = '';

    if (window.SiemEngine) {
        window.SiemEngine.showToast(`Provisioned analyst ${fullName} (${role})`, 'success');
        window.SiemEngine.playAlertSound('LOW');
    }

    if (statusMsg) {
        statusMsg.innerHTML = '<span style="color:var(--green);"><i class="fas fa-check-circle"></i> Provisioned</span>';
        setTimeout(() => { statusMsg.innerHTML = ''; }, 3000);
    }
}

// ── Toggle User Status ──
function toggleUserStatus(userId) {
    const user = allUsers.find(u => u.id === userId);
    if (!user) return;

    user.status = user.status === 'Active' ? 'Suspended' : 'Active';
    saveUsersCache();
    renderUsers();
    updateUserStats();

    if (window.SiemEngine) {
        window.SiemEngine.showToast(`User ${user.username} is now ${user.status}`, user.status === 'Active' ? 'success' : 'warning');
    }
}

// ── Delete User ──
function deleteUser(userId) {
    const user = allUsers.find(u => u.id === userId);
    if (!user) return;

    if (confirm(`Revoke all credentials for ${user.full_name} (${user.username})?`)) {
        allUsers = allUsers.filter(u => u.id !== userId);
        saveUsersCache();
        applyUserFilters();
        updateUserStats();

        if (window.SiemEngine) {
            window.SiemEngine.showToast(`Revoked credentials for ${user.full_name}`, 'error');
        }
    }
}

// ── User Modal Inspection & Editing ──
function viewUserModal(userId) {
    const user = allUsers.find(u => u.id === userId);
    if (!user) return;

    const modal = document.getElementById('userModal');
    const content = document.getElementById('userModalContent');
    if (!modal || !content) return;

    const initials = user.full_name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();

    content.innerHTML = `
        <div class="panel-header" style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border-color);padding-bottom:12px;margin-bottom:16px;">
            <div style="display:flex;align-items:center;gap:12px;">
                <div class="user-avatar-badge" style="width:42px;height:42px;font-size:1rem;">${initials}</div>
                <div>
                    <h3 style="margin:0;font-size:1.1rem;display:flex;align-items:center;gap:8px;">
                        ${user.full_name}
                        ${getRoleBadge(user.role)}
                    </h3>
                    <div style="font-size:0.75rem;color:var(--text-muted);font-family:'JetBrains Mono',monospace;">${user.id} · ${user.username}</div>
                </div>
            </div>
            <button class="filter-btn" onclick="closeUserModal()" style="padding:4px 8px;"><i class="fas fa-times"></i></button>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px;">
            <div>
                <label style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px;">Display Name</label>
                <input type="text" id="editUserName" value="${user.full_name}" class="siem-input" style="width:100%;">
            </div>
            <div>
                <label style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px;">Email Address</label>
                <input type="email" id="editUserEmail" value="${user.email}" class="siem-input" style="width:100%;">
            </div>
            <div>
                <label style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px;">RBAC Role</label>
                <select id="editUserRole" class="siem-select" style="width:100%;">
                    <option value="Admin" ${user.role === 'Admin' ? 'selected' : ''}>SOC Administrator (L3)</option>
                    <option value="SOC Lead" ${user.role === 'SOC Lead' ? 'selected' : ''}>SOC Lead (Tier 2)</option>
                    <option value="Threat Hunter" ${user.role === 'Threat Hunter' ? 'selected' : ''}>Threat Hunter</option>
                    <option value="Incident Responder" ${user.role === 'Incident Responder' ? 'selected' : ''}>Incident Responder</option>
                    <option value="Security Analyst" ${user.role === 'Security Analyst' ? 'selected' : ''}>Security Analyst (L1)</option>
                    <option value="Compliance Auditor" ${user.role === 'Compliance Auditor' ? 'selected' : ''}>Compliance Auditor</option>
                </select>
            </div>
            <div>
                <label style="font-size:0.7rem;color:var(--text-secondary);text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px;">Account Status</label>
                <select id="editUserStatus" class="siem-select" style="width:100%;">
                    <option value="Active" ${user.status === 'Active' ? 'selected' : ''}>Active</option>
                    <option value="Suspended" ${user.status === 'Suspended' ? 'selected' : ''}>Suspended</option>
                    <option value="Inactive" ${user.status === 'Inactive' ? 'selected' : ''}>Inactive / Offline</option>
                </select>
            </div>
        </div>

        <div style="background:var(--bg-primary);border:1px solid var(--border-color);border-radius:var(--radius-sm);padding:14px;margin-bottom:20px;">
            <h4 style="font-size:0.8rem;margin-bottom:10px;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
                <i class="fas fa-shield-halved text-green"></i> Security Clearances & PAM Telemetry
            </h4>
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:10px;font-size:0.72rem;">
                <div>
                    <span style="color:var(--text-muted);display:block;">2FA / MFA Enforced:</span>
                    <strong style="color:${user.mfa_enabled ? 'var(--green)' : 'var(--yellow)'};">${user.mfa_enabled ? 'Yes (FIDO2 / TOTP)' : 'Pending Setup'}</strong>
                </div>
                <div>
                    <span style="color:var(--text-muted);display:block;">Active Sessions:</span>
                    <strong>${user.sessions} concurrent</strong>
                </div>
                <div>
                    <span style="color:var(--text-muted);display:block;">Last Auth IP:</span>
                    <code style="color:var(--blue);">${user.ip_address || '127.0.0.1'}</code>
                </div>
                <div>
                    <span style="color:var(--text-muted);display:block;">Created Date:</span>
                    <span>${new Date(user.created_at).toLocaleDateString()}</span>
                </div>
                <div>
                    <span style="color:var(--text-muted);display:block;">Session Idle Timeout:</span>
                    <span>15 minutes</span>
                </div>
                <div>
                    <span style="color:var(--text-muted);display:block;">Audit Log Trail:</span>
                    <span style="color:var(--green);"><i class="fas fa-check"></i> Enabled</span>
                </div>
            </div>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--border-color);padding-top:14px;">
            <button class="filter-btn" style="background:var(--red);color:#fff;" onclick="deleteUser('${user.id}'); closeUserModal();">
                <i class="fas fa-trash"></i> Revoke Account
            </button>
            <div style="display:flex;gap:8px;">
                <button class="filter-btn" onclick="closeUserModal()">Cancel</button>
                <button class="filter-btn" style="background:var(--green);color:#000;font-weight:700;" onclick="saveUserChanges('${user.id}')">
                    <i class="fas fa-save"></i> Save Changes
                </button>
            </div>
        </div>
    `;

    modal.classList.add('active');
}

function saveUserChanges(userId) {
    const user = allUsers.find(u => u.id === userId);
    if (!user) return;

    const nameInput = document.getElementById('editUserName');
    const emailInput = document.getElementById('editUserEmail');
    const roleInput = document.getElementById('editUserRole');
    const statusInput = document.getElementById('editUserStatus');

    if (nameInput) user.full_name = nameInput.value.trim();
    if (emailInput) user.email = emailInput.value.trim();
    if (roleInput) user.role = roleInput.value;
    if (statusInput) user.status = statusInput.value;

    saveUsersCache();
    applyUserFilters();
    updateUserStats();
    closeUserModal();

    if (window.SiemEngine) {
        window.SiemEngine.showToast(`Updated operator ${user.full_name}`, 'success');
    }
}

function closeUserModal() {
    const modal = document.getElementById('userModal');
    if (modal) modal.classList.remove('active');
}

// ── Export Users to CSV ──
function exportUsersCSV() {
    if (filteredUsers.length === 0) {
        if (window.SiemEngine) window.SiemEngine.showToast('No users to export', 'warning');
        return;
    }

    const data = filteredUsers.map(u => ({
        ID: u.id,
        Name: u.full_name,
        Username: u.username,
        Email: u.email,
        Role: u.role,
        Status: u.status,
        MFA: u.mfa_enabled ? 'Enforced' : 'Disabled',
        Sessions: u.sessions,
        IP_Address: u.ip_address,
        Last_Login: u.last_login
    }));

    if (window.SiemEngine) {
        window.SiemEngine.exportToCSV(data, `soc_analysts_${new Date().toISOString().substring(0, 10)}.csv`);
        window.SiemEngine.showToast(`Exported ${filteredUsers.length} analysts to CSV`, 'success');
    }
}

// ── Timestamp Sync ──
function updateLastUpdate() {
    const now = new Date().toLocaleTimeString();
    const lastUpdateEl = document.getElementById('lastUpdate');
    const statusBarEl = document.getElementById('statusBarRight');

    if (lastUpdateEl) lastUpdateEl.textContent = now;
    if (statusBarEl) statusBarEl.textContent = `Last sync: ${now}`;
}

// ── DOM Initialization ──
document.addEventListener('DOMContentLoaded', () => {
    loadUsers();

    // Close modal on click outside or Escape
    const modal = document.getElementById('userModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeUserModal();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeUserModal();
    });

    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadUsers();
    }, 30000);
});