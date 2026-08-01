document.addEventListener('DOMContentLoaded', function () {
    const scannerForm = document.getElementById('scannerForm');
    const urlInput = document.getElementById('urlInput');
    const submitBtn = document.getElementById('scanSubmitBtn');
    const spinner = document.getElementById('scanSpinner');
    const loadingState = document.getElementById('scanLoadingState');

    if (scannerForm) {
        scannerForm.addEventListener('submit', function (e) {
            e.preventDefault();

            const urlValue = urlInput ? urlInput.value.trim() : '';

            if (!urlValue) {
                showToast('Please enter a valid website URL before starting scan.', 'warning');
                return;
            }

            // UI Loading state
            if (submitBtn) submitBtn.disabled = true;
            if (spinner) spinner.classList.remove('d-none');
            if (loadingState) loadingState.classList.remove('d-none');

            // Send AJAX scan request
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ url: urlValue })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.redirect_url) {
                    window.location.href = data.redirect_url;
                } else {
                    showToast(data.error || 'Scan failed. Please check the URL format.', 'danger');
                    if (submitBtn) submitBtn.disabled = false;
                    if (spinner) spinner.classList.add('d-none');
                    if (loadingState) loadingState.classList.add('d-none');
                }
            })
            .catch(error => {
                showToast('Network error occurred during analysis: ' + error.message, 'danger');
                if (submitBtn) submitBtn.disabled = false;
                if (spinner) spinner.classList.add('d-none');
                if (loadingState) loadingState.classList.add('d-none');
            });
        });
    }
});
