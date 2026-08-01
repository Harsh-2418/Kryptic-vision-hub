// Instant Dark / Light Theme Engine for Kryptic Vision Hub

(function () {
    // 1. Immediately apply saved theme to prevent FOUC (Flash of Unstyled Content)
    const savedTheme = localStorage.getItem('kryptic_theme') || 'light';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
})();

function getCurrentTheme() {
    return document.documentElement.getAttribute('data-bs-theme') || 'light';
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('kryptic_theme', theme);

    // Set cookie for backend sync
    document.cookie = `theme_mode=${theme}; path=/; max-age=31536000`;

    // Update Theme Toggle Buttons UI if present
    const toggleIcon = document.getElementById('themeToggleIcon');
    const toggleText = document.getElementById('themeToggleText');
    
    if (toggleIcon) {
        if (theme === 'dark') {
            toggleIcon.className = 'bi bi-sun-fill text-warning';
            if (toggleText) toggleText.textContent = 'Light Mode';
        } else {
            toggleIcon.className = 'bi bi-moon-stars-fill text-primary';
            if (toggleText) toggleText.textContent = 'Dark Mode';
        }
    }

    // Sync settings radio buttons if on Settings page
    const radioLight = document.getElementById('themeLight');
    const radioDark = document.getElementById('themeDark');
    if (radioLight && radioDark) {
        if (theme === 'dark') {
            radioDark.checked = true;
        } else {
            radioLight.checked = true;
        }
    }

    // Reconfigure Chart.js dynamically
    updateCharts(theme);
}

function toggleTheme() {
    const current = getCurrentTheme();
    const nextTheme = current === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme);
}

function updateCharts(theme) {
    if (typeof Chart === 'undefined') return;

    const textColor = theme === 'dark' ? '#F8FAFC' : '#0F172A';
    const gridColor = theme === 'dark' ? '#334155' : '#E2E8F0';

    Chart.helpers.each(Chart.instances, function (chart) {
        if (chart.options.plugins && chart.options.plugins.legend) {
            chart.options.plugins.legend.labels.color = textColor;
        }

        if (chart.options.scales) {
            if (chart.options.scales.x) {
                chart.options.scales.x.ticks.color = textColor;
                chart.options.scales.x.grid.color = gridColor;
            }
            if (chart.options.scales.y) {
                chart.options.scales.y.ticks.color = textColor;
                chart.options.scales.y.grid.color = gridColor;
            }
        }
        chart.update();
    });
}

document.addEventListener('DOMContentLoaded', function () {
    const currentTheme = getCurrentTheme();
    applyTheme(currentTheme);

    const themeToggleBtn = document.getElementById('themeToggleBtn');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', function (e) {
            e.preventDefault();
            toggleTheme();
        });
    }
});
