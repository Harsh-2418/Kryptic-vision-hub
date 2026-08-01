document.addEventListener('DOMContentLoaded', function () {
    const pieCtx = document.getElementById('threatPieChart');
    const barCtx = document.getElementById('moduleBarChart');
    const lineCtx = document.getElementById('dailyLineChart');
    const doughnutCtx = document.getElementById('safeDoughnutChart');

    if (!pieCtx && !barCtx) return;

    fetch('/api/dashboard_charts')
        .then(response => response.json())
        .then(data => {
            const currentTheme = document.documentElement.getAttribute('data-bs-theme') || 'light';
            const textColor = currentTheme === 'dark' ? '#F8FAFC' : '#0F172A';
            const gridColor = currentTheme === 'dark' ? '#334155' : '#E2E8F0';

            // 1. Pie Chart: Threat Distribution
            if (pieCtx) {
                new Chart(pieCtx, {
                    type: 'pie',
                    data: {
                        labels: data.threat_distribution.labels,
                        datasets: [{
                            data: data.threat_distribution.data,
                            backgroundColor: ['#16A34A', '#F59E0B', '#DC2626']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: { color: textColor }
                            }
                        }
                    }
                });
            }

            // 2. Bar Chart: Module Usage
            if (barCtx) {
                new Chart(barCtx, {
                    type: 'bar',
                    data: {
                        labels: data.module_usage.labels,
                        datasets: [{
                            label: 'Analyses Count',
                            data: data.module_usage.data,
                            backgroundColor: ['#2563EB', '#1E293B', '#F59E0B', '#0EA5E9', '#DC2626'],
                            borderRadius: 8
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { ticks: { color: textColor }, grid: { color: gridColor } },
                            y: { beginAtZero: true, ticks: { color: textColor }, grid: { color: gridColor } }
                        }
                    }
                });
            }

            // 3. Line Chart: Daily Scans
            if (lineCtx) {
                new Chart(lineCtx, {
                    type: 'line',
                    data: {
                        labels: data.daily_scans.labels,
                        datasets: [{
                            label: 'Daily Scans',
                            data: data.daily_scans.data,
                            borderColor: '#3B82F6',
                            backgroundColor: 'rgba(59, 130, 246, 0.15)',
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { labels: { color: textColor } }
                        },
                        scales: {
                            x: { ticks: { color: textColor }, grid: { color: gridColor } },
                            y: { beginAtZero: true, ticks: { color: textColor }, grid: { color: gridColor } }
                        }
                    }
                });
            }

            // 4. Doughnut Chart: Safe vs Dangerous
            if (doughnutCtx) {
                new Chart(doughnutCtx, {
                    type: 'doughnut',
                    data: {
                        labels: data.safe_vs_dangerous.labels,
                        datasets: [{
                            data: data.safe_vs_dangerous.data,
                            backgroundColor: ['#16A34A', '#DC2626']
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: { color: textColor }
                            }
                        }
                    }
                });
            }
        })
        .catch(err => console.error('Failed to load chart analytics:', err));
});
