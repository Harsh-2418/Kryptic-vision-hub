document.addEventListener('DOMContentLoaded', function () {
    const wifiForm = document.getElementById('wifiForm');
    const ssidInput = document.getElementById('ssid');

    if (wifiForm) {
        wifiForm.addEventListener('submit', function (e) {
            if (!ssidInput || !ssidInput.value.trim()) {
                e.preventDefault();
                showToast('Please enter an SSID name.', 'warning');
            }
        });
    }
});
