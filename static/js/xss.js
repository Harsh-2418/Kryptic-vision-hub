document.addEventListener('DOMContentLoaded', function () {
    const loadSampleBtn = document.getElementById('loadXssSampleBtn');
    const codeSnippetInput = document.getElementById('code_snippet');
    const xssForm = document.getElementById('xssForm');

    if (loadSampleBtn && codeSnippetInput) {
        loadSampleBtn.addEventListener('click', function () {
            codeSnippetInput.value = `// Unsafe JavaScript DOM Rendering:
const userInput = location.hash.substring(1);
document.getElementById('welcome-msg').innerHTML = 'Welcome back ' + userInput;

// Unsafe Jinja Template Bypass:
// <div>{{ search_query | safe }}</div>`;
            showToast('Sample vulnerable XSS snippet loaded.', 'info');
        });
    }

    if (xssForm) {
        xssForm.addEventListener('submit', function (e) {
            if (!codeSnippetInput || !codeSnippetInput.value.trim()) {
                e.preventDefault();
                showToast('Please paste a template or JavaScript snippet to analyze.', 'warning');
            }
        });
    }
});
