// ════════════════════════════════════════════════════════════
//  THEME ENGINE — Next-Gen SOC Dark / Executive Light Mode
// ════════════════════════════════════════════════════════════

(function() {
    window.toggleTheme = function() {
        const current = document.documentElement.getAttribute('data-theme') || 
                        document.body.getAttribute('data-theme') || 
                        localStorage.getItem('siem_theme') || 'dark';
        const newTheme = current === 'light' ? 'dark' : 'light';
        applyTheme(newTheme);
    };

    window.applyTheme = function(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.body.setAttribute('data-theme', theme);
        localStorage.setItem('siem_theme', theme);

        // Update all theme toggle buttons across the DOM
        const toggles = document.querySelectorAll('.theme-toggle, #themeToggle');
        toggles.forEach(toggle => {
            const icon = toggle.querySelector('i');
            const label = toggle.querySelector('#themeLabel') || toggle.querySelector('.theme-label');
            if (theme === 'light') {
                if (icon) icon.className = 'fas fa-sun';
                if (label) label.textContent = 'Light';
            } else {
                if (icon) icon.className = 'fas fa-moon';
                if (label) label.textContent = 'Dark';
            }
        });

        // Trigger custom event for D3 / Leaflet / Chart.js re-renders
        window.dispatchEvent(new CustomEvent('siemThemeChanged', { detail: { theme } }));
        if (typeof renderCharts === 'function') renderCharts();
    };

    window.loadTheme = function() {
        const saved = localStorage.getItem('siem_theme') || 'dark';
        applyTheme(saved);
    };

    // Auto-initialize as early as possible
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadTheme);
    } else {
        loadTheme();
    }
})();