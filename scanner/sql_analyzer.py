import re

class SQLAnalyzer:
    """
    Static Code Analyzer for SQL Injection Vulnerabilities.
    Performs static pattern matching on user-submitted backend code snippets (Python, PHP, Node.js, Java, SQL).
    Does NOT execute any code or query databases.
    """

    PATTERNS = [
        # Pattern 1: Python f-strings in SQL queries
        {
            'pattern': r'execute\s*\(\s*f["\'].*SELECT|UPDATE|INSERT|DELETE.*\{',
            'severity': 'High',
            'score': 40,
            'issue': 'Python f-string format detected directly inside SQL query execution.',
            'description': 'Constructing SQL statements using Python f-strings allows user-controlled inputs to alter SQL query logic.'
        },
        # Pattern 2: String concatenation using + in SQL strings
        {
            'pattern': r'(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*\+.*["\']',
            'severity': 'High',
            'score': 35,
            'issue': 'Dynamic string concatenation (`+`) detected inside SQL query string.',
            'description': 'Concatenating variables into SQL strings creates a direct SQL Injection risk.'
        },
        # Pattern 3: String formatting using % or .format() in SQL
        {
            'pattern': r'["\'].*(SELECT|INSERT|UPDATE|DELETE).*%s|\.format\(',
            'severity': 'Medium',
            'score': 25,
            'issue': 'Legacy string interpolation (`%s` or `.format()`) used in SQL string.',
            'description': 'String interpolation before passing to the SQL driver bypasses database parameterization.'
        },
        # Pattern 4: PHP string concatenation into SQL
        {
            'pattern': r'\$sql\s*=.*\$_(GET|POST|REQUEST|COOKIE)[\s\.]',
            'severity': 'Critical',
            'score': 45,
            'issue': 'Direct PHP global input array (`$_GET`/`$_POST`) concatenated into SQL variable.',
            'description': 'Embedding raw PHP request parameters directly into SQL queries causes critical SQL injection.'
        },
        # Pattern 5: Node.js / JavaScript template literal in SQL query call
        {
            'pattern': r'query\s*\(\s*`.*SELECT|UPDATE|INSERT|DELETE.*\${',
            'severity': 'High',
            'score': 35,
            'issue': 'Node.js template literal (`${var}`) detected inside SQL query call.',
            'description': 'Template literals evaluate variables into the SQL string before database engine parsing.'
        },
        # Pattern 6: Unsanitized input variable appended directly into query
        {
            'pattern': r'WHERE\s+[a-zA-Z0-9_]+\s*=\s*[\'"].*[\'"]?\s*\+',
            'severity': 'Medium',
            'score': 20,
            'issue': 'Dynamic WHERE clause construction without parameter placeholders.',
            'description': 'Filtering query parameters via direct concatenation prevents query plan caching and exposes database structure.'
        }
    ]

    @staticmethod
    def analyze_code(code_snippet):
        if not code_snippet or not code_snippet.strip():
            return {
                'success': False,
                'error': 'Code snippet cannot be empty.'
            }

        snippet = code_snippet.strip()
        detected_issues = []
        total_risk_score = 0
        highest_severity_rank = 0
        severity_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

        for item in SQLAnalyzer.PATTERNS:
            if re.search(item['pattern'], snippet, re.IGNORECASE):
                detected_issues.append({
                    'issue': item['issue'],
                    'severity': item['severity'],
                    'description': item['description']
                })
                total_risk_score += item['score']
                rank = severity_map.get(item['severity'], 1)
                if rank > highest_severity_rank:
                    highest_severity_rank = rank

        risk_score = min(total_risk_score, 100)

        # Map highest severity rank back to label
        rank_to_severity = {0: 'Safe', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        overall_severity = rank_to_severity[highest_severity_rank]

        if risk_score == 0:
            status = "Safe - No Pattern Anomalies Detected"
            status_class = "success"
            recommendation = "No obvious dynamic SQL concatenation patterns found. Continue using prepared statements and parameterized queries."
            safe_example = "-- Good Practice Example (Python/SQLite):\ncursor.execute('SELECT * FROM users WHERE email = ?', (email_input,))"
        else:
            status = f"Potential SQL Injection Risk ({overall_severity} Severity)"
            status_class = "danger" if overall_severity in ['High', 'Critical'] else "warning"
            recommendation = "Refactor database access to use parameterized queries, prepared statements, or a trusted Object-Relational Mapper (ORM)."
            safe_example = """# SECURE PARAMETERIZED QUERY EXAMPLES:

# Python (sqlite3 / psycopg2):
cursor.execute("SELECT * FROM users WHERE email = %s", (email_input,))

# PHP (PDO):
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
$stmt->execute(['email' => $emailInput]);

# Node.js (pg / mysql2):
db.query('SELECT * FROM users WHERE email = ?', [emailInput]);"""

        return {
            'success': True,
            'code_snippet': snippet,
            'risk_score': risk_score,
            'severity': overall_severity,
            'status': status,
            'status_class': status_class,
            'issues': detected_issues,
            'recommendation': recommendation,
            'safe_example': safe_example
        }
