// ════════════════════════════════════════════════════════════
//  SETTINGS CONTROLLER — SOC Engine Configuration
// ════════════════════════════════════════════════════════════

function loadSettings() {
    const currentBase = localStorage.getItem('siem_api_base') || "http://100.90.174.77:5000";
    const refreshSec = localStorage.getItem('siem_refresh_sec') || "15";
    const sound = localStorage.getItem('siem_sound_enabled') === 'true';
    const currentToken = localStorage.getItem('siem_mapbox_token') || window.MAPBOX_TOKEN || "";

    const inputUrl = document.getElementById('apiUrl');
    const inputToken = document.getElementById('mapboxToken');
    const inputRefresh = document.getElementById('refreshInterval');
    const toggleSound = document.getElementById('soundAlerts');
    const currentTheme = localStorage.getItem('siem_theme') || 'dark';

    if (inputUrl) inputUrl.value = currentBase;
    if (inputToken) inputToken.value = currentToken;
    if (inputRefresh) inputRefresh.value = refreshSec;
    if (toggleSound) toggleSound.checked = sound;

    const themeSelect = document.getElementById('themeSelect');
    if (themeSelect) themeSelect.value = currentTheme;
}

function saveSettings() {
    const apiUrl = document.getElementById('apiUrl')?.value.trim() || "http://100.90.174.77:5000";
    const mapboxToken = document.getElementById('mapboxToken')?.value.trim() || "";
    const refreshSec = document.getElementById('refreshInterval')?.value || "15";
    const sound = document.getElementById('soundAlerts')?.checked || false;
    const theme = document.getElementById('themeSelect')?.value || 'dark';

    SiemEngine.setApiBase(apiUrl);
    if (mapboxToken) {
        localStorage.setItem('siem_mapbox_token', mapboxToken);
        window.MAPBOX_TOKEN = mapboxToken;
    }
    localStorage.setItem('siem_refresh_sec', refreshSec);
    localStorage.setItem('siem_sound_enabled', sound);
    applyTheme(theme);

    SiemEngine.showToast("SIEM settings saved successfully", "success", "Configuration Saved");
}

async function testConnection() {
    const apiUrl = document.getElementById('apiUrl')?.value.trim() || "http://100.90.174.77:5000";
    const statusEl = document.getElementById('testStatus');
    if (statusEl) {
        statusEl.innerHTML = `<span style="color:var(--orange)"><i class="fas fa-spinner fa-spin"></i> Probing ${apiUrl}...</span>`;
    }

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);
        const resp = await fetch(`${apiUrl}/api/stats`, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (resp.ok) {
            if (statusEl) statusEl.innerHTML = `<span style="color:var(--green);font-weight:700;"><i class="fas fa-circle-check"></i> Connection Successful! SIEM Core online</span>`;
            SiemEngine.showToast("Connected to live SIEM server successfully", "success");
        } else {
            if (statusEl) statusEl.innerHTML = `<span style="color:var(--orange);font-weight:600;"><i class="fas fa-triangle-exclamation"></i> Server returned HTTP ${resp.status}</span>`;
        }
    } catch (err) {
        if (statusEl) {
            statusEl.innerHTML = `<span style="color:var(--red);font-weight:600;"><i class="fas fa-plug-circle-xmark"></i> Host unreachable (${err.message}). Using simulation fallback.</span>`;
        }
        SiemEngine.showToast("Host unreachable. Simulation mode will remain active.", "warning");
    }
}

function setPreset(url) {
    const inputUrl = document.getElementById('apiUrl');
    if (inputUrl) {
        inputUrl.value = url;
        SiemEngine.showToast(`Set endpoint to ${url}`, 'info');
    }
}

function resetDefaults() {
    if (confirm("Reset configuration to default Tailscale SIEM server?")) {
        localStorage.removeItem('siem_api_base');
        localStorage.removeItem('siem_refresh_sec');
        localStorage.removeItem('siem_sound_enabled');
        loadSettings();
        SiemEngine.showToast("Settings reset to defaults", "success");
    }
}

document.addEventListener('DOMContentLoaded', loadSettings);