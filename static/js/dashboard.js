document.addEventListener('DOMContentLoaded', function () {
    const quickScanForm = document.getElementById('quickScanForm');
    const quickUrlInput = document.getElementById('quickUrlInput');

    if (quickScanForm) {
        quickScanForm.addEventListener('submit', function (e) {
            const val = quickUrlInput ? quickUrlInput.value.trim() : '';
            if (!val) {
                e.preventDefault();
                showToast('Please enter a target URL to scan.', 'warning');
            }
        });
    }
});
