import re

class XSSAnalyzer:
    """
    Static Code Analyzer for Cross-Site Scripting (XSS) Vulnerabilities.
    Analyzes HTML, JavaScript, PHP, Jinja/Flask templates, and React snippets for unsafe output rendering.
    Does NOT execute JavaScript or render pages.
    """

    PATTERNS = [
        # Pattern 1: JS innerHTML / outerHTML assignment
        {
            'pattern': r'\.(innerHTML|outerHTML)\s*=\s*',
            'severity': 'High',
            'score': 35,
            'issue': 'Direct assignment to `innerHTML` or `outerHTML`.',
            'description': 'Assigning untrusted data to `innerHTML` causes the browser to parse strings as executable HTML/JavaScript.'
        },
        # Pattern 2: document.write()
        {
            'pattern': r'document\.write\s*\(',
            'severity': 'Critical',
            'score': 45,
            'issue': 'Use of `document.write()`.',
            'description': '`document.write()` injects raw unescaped strings directly into the DOM document stream.'
        },
        # Pattern 3: React dangerouslySetInnerHTML
        {
            'pattern': r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:',
            'severity': 'High',
            'score': 35,
            'issue': 'Use of React `dangerouslySetInnerHTML`.',
            'description': 'Bypasses React DOM sanitization protection and renders raw HTML strings directly into components.'
        },
        # Pattern 4: Jinja2 / Flask safe filter
        {
            'pattern': r'\{\{\s*.*\|\s*safe\s*\}\}',
            'severity': 'Medium',
            'score': 25,
            'issue': 'Explicit bypass of Jinja auto-escaping via `| safe` filter.',
            'description': 'The `| safe` filter disables Flask/Jinja automatic HTML entity encoding for the variable.'
        },
        # Pattern 5: PHP raw echo of request globals
        {
            'pattern': r'echo\s+\$_(GET|POST|REQUEST)\[',
            'severity': 'Critical',
            'score': 45,
            'issue': 'PHP `echo` of unescaped request global array (`$_GET`/`$_POST`).',
            'description': 'Outputting raw request parameters directly into HTML response leads to Reflected XSS.'
        },
        # Pattern 6: Unquoted or dynamic event handlers in HTML
        {
            'pattern': r'on(click|load|mouseover|error)\s*=\s*["\']?.*(\$|\+|location)',
            'severity': 'High',
            'score': 30,
            'issue': 'Dynamic inline JavaScript event handler (`onclick`/`onerror`) containing variables.',
            'description': 'Interpolating variables into inline HTML attributes opens DOM-based XSS vectors.'
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

        for item in XSSAnalyzer.PATTERNS:
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
        rank_to_severity = {0: 'Safe', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        overall_severity = rank_to_severity[highest_severity_rank]

        if risk_score == 0:
            status = "Safe - Safe Output Patterns Detected"
            status_class = "success"
            recommendation = "No unescaped DOM rendering or raw output practices found. Rely on context-aware HTML escaping and Content Security Policy (CSP)."
            safe_example = "// Good Practice Example (JavaScript):\nelement.textContent = userInput;"
        else:
            status = f"Potential XSS Vulnerability ({overall_severity} Severity)"
            status_class = "danger" if overall_severity in ['High', 'Critical'] else "warning"
            recommendation = "Use `textContent` instead of `innerHTML`, apply context-aware HTML entity encoding, and enforce Content Security Policy (CSP) headers."
            safe_example = """<!-- SECURE OUTPUT ENCODING EXAMPLES: -->

<!-- Vanilla JavaScript: -->
element.textContent = userInput; // Automatically treats input as plain text

<!-- PHP: -->
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');

<!-- Flask / Jinja2: -->
{{ userInput }} <!-- Jinja auto-escapes HTML characters by default -->

<!-- React: -->
<div>{userInput}</div> <!-- React escapes variables automatically -->"""

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
