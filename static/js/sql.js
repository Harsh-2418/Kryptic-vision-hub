document.addEventListener('DOMContentLoaded', function () {
    const loadSampleBtn = document.getElementById('loadSqlSampleBtn');
    const codeSnippetInput = document.getElementById('code_snippet');
    const sqlForm = document.getElementById('sqlForm');

    if (loadSampleBtn && codeSnippetInput) {
        loadSampleBtn.addEventListener('click', function () {
            codeSnippetInput.value = `# Insecure Python SQL Concatenation Pattern:
user_input = request.form.get('user_id')
query = "SELECT * FROM users WHERE id = '" + user_input + "'"
cursor.execute(query)

# Insecure f-string Pattern:
# query = f"SELECT * FROM accounts WHERE email = '{email}'"`;
            showToast('Sample vulnerable SQL query snippet loaded.', 'info');
        });
    }

    if (sqlForm) {
        sqlForm.addEventListener('submit', function (e) {
            if (!codeSnippetInput || !codeSnippetInput.value.trim()) {
                e.preventDefault();
                showToast('Please paste a code snippet or query to analyze.', 'warning');
            }
        });
    }
});
