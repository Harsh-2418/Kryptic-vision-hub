document.addEventListener('DOMContentLoaded', function () {
    const evilTwinForm = document.getElementById('evilTwinForm');
    const currentSsid = document.getElementById('current_ssid');
    const currentBssid = document.getElementById('current_bssid');

    if (evilTwinForm) {
        evilTwinForm.addEventListener('submit', function (e) {
            if (!currentSsid || !currentSsid.value.trim() || !currentBssid || !currentBssid.value.trim()) {
                e.preventDefault();
                showToast('Please enter both active SSID and BSSID (MAC Address).', 'warning');
            }
        });
    }
});
