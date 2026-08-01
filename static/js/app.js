document.addEventListener('DOMContentLoaded', function () {
    // Scroll to Top Button Handler
    const scrollToTopBtn = document.getElementById('scrollToTopBtn');
    if (scrollToTopBtn) {
        window.addEventListener('scroll', function () {
            if (window.scrollY > 300) {
                scrollToTopBtn.classList.remove('d-none');
            } else {
                scrollToTopBtn.classList.add('d-none');
            }
        });

        scrollToTopBtn.addEventListener('click', function () {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }

    // Auto dismiss flash alerts after 5 seconds
    const alerts = document.querySelectorAll('#flash-container .alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// Helper function to render dynamically generated toast alerts
function showToast(message, type = 'info') {
    const flashContainer = document.getElementById('flash-container');
    if (!flashContainer) return;

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show shadow-sm border-0 d-flex align-items-center gap-2`;
    alertDiv.setAttribute('role', 'alert');

    let iconHtml = '<i class="bi bi-info-circle-fill text-info fs-5"></i>';
    if (type === 'success') iconHtml = '<i class="bi bi-check-circle-fill text-success fs-5"></i>';
    if (type === 'danger') iconHtml = '<i class="bi bi-exclamation-triangle-fill text-danger fs-5"></i>';
    if (type === 'warning') iconHtml = '<i class="bi bi-exclamation-circle-fill text-warning fs-5"></i>';

    alertDiv.innerHTML = `
        ${iconHtml}
        <div>${message}</div>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

    flashContainer.appendChild(alertDiv);

    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alertDiv);
        bsAlert.close();
    }, 5000);
}
