import re
import socket
import ssl
from urllib.parse import urlparse
import requests

class FeatureExtractor:
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'bank', 'secure', 'update', 
        'wallet', 'paypal', 'signin', 'account', 'password',
        'authenticate', 'billing', 'confirm', 'credential'
    ]

    SUSPICIOUS_TLDS = [
        '.zip', '.top', '.xyz', '.work', '.cc', '.gq', 
        '.tk', '.ml', '.cf', '.ga', '.biz', '.download', 
        '.racing', '.cam', '.monster', '.fit', '.rest', '.country'
    ]

    def __init__(self, url):
        self.raw_url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.hostname or ""
        self.path = self.parsed_url.path or ""

    def check_http_scheme(self):
        """Rule 1: Uses HTTP instead of HTTPS (+20)"""
        if self.parsed_url.scheme.lower() == 'http':
            return True, 20, "Uses HTTP protocol instead of secure HTTPS."
        return False, 0, "HTTPS enabled."

    def check_at_symbol(self):
        """Rule 2: Contains @ symbol (+25)"""
        if '@' in self.raw_url:
            return True, 25, "Contains '@' symbol which can obscure the real destination host."
        return False, 0, "No '@' symbol found."

    def check_ip_address(self):
        """Rule 3: Contains IP Address (+30)"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, self.domain):
            return True, 30, "Raw IP address used instead of a legitimate domain name."
        return False, 0, "Domain name used (no raw IP)."

    def check_dots_count(self):
        """Rule 4: More than 4 dots (+10)"""
        dot_count = self.raw_url.count('.')
        if dot_count > 4:
            return True, 10, f"Excessive number of dots detected ({dot_count} dots)."
        return False, 0, f"Normal dot count ({dot_count} dots)."

    def check_double_slash(self):
        """Rule 5: More than one // (+10)"""
        # Find position of initial '://'
        temp_url = self.raw_url
        if '://' in temp_url:
            temp_url = temp_url.split('://', 1)[1]
        if '//' in temp_url:
            return True, 10, "Contains suspicious double slash '//' in URL path."
        return False, 0, "No extra double slash detected."

    def check_hyphens(self):
        """Rule 6: Contains many hyphens (+10)"""
        hyphen_count = self.raw_url.count('-')
        if hyphen_count >= 3:
            return True, 10, f"High number of hyphens detected ({hyphen_count} hyphens)."
        return False, 0, "Normal hyphen usage."

    def check_url_length(self):
        """Rule 7: Very long URL (+15)"""
        if len(self.raw_url) > 75:
            return True, 15, f"Unusually long URL structure ({len(self.raw_url)} characters)."
        return False, 0, "URL length is standard."

    def check_suspicious_keywords(self):
        """Rule 8: Uses suspicious keywords (+20)"""
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in self.raw_url.lower()]
        if found_keywords:
            return True, 20, f"Contains sensitive keyword(s): {', '.join(found_keywords)}."
        return False, 0, "No phishing keywords found."

    def check_suspicious_tld(self):
        """Rule 12: Suspicious top-level domains (+10)"""
        domain_lower = self.domain.lower()
        found_tlds = [tld for tld in self.SUSPICIOUS_TLDS if domain_lower.endswith(tld)]
        if found_tlds:
            return True, 10, f"Uses high-risk Top Level Domain ({found_tlds[0]})."
        return False, 0, "Standard Top Level Domain."

    def check_redirects(self):
        """Rule 10: Multiple redirects (+15)"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) KrypticVisionHub/1.0'}
            response = requests.head(self.raw_url, headers=headers, allow_redirects=True, timeout=3)
            if len(response.history) > 1:
                return True, 15, f"Multiple URL redirects detected ({len(response.history)} redirects)."
        except Exception:
            pass
        return False, 0, "Direct connection (no multiple redirects)."

    def check_ssl_certificate(self):
        """Rule 11: Invalid SSL (+25)"""
        if self.parsed_url.scheme.lower() != 'https':
            return True, 25, "No SSL/TLS certificate (HTTP mode)."
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    ssock.getpeercert()
            return False, 0, "Valid SSL/TLS certificate detected."
        except Exception as e:
            return True, 25, f"SSL/TLS validation failed or untrusted certificate: {str(e)}"

    def check_domain_age_heuristic(self):
        """Rule 9: Domain age / connection anomaly heuristic (+20)"""
        try:
            socket.gethostbyname(self.domain)
            # Domain resolves cleanly
            return False, 0, "Domain host resolved cleanly."
        except Exception:
            return True, 20, "Domain resolution anomaly or domain could not be resolved."

    def extract_all_features(self):
        rules = [
            self.check_http_scheme,
            self.check_at_symbol,
            self.check_ip_address,
            self.check_dots_count,
            self.check_double_slash,
            self.check_hyphens,
            self.check_url_length,
            self.check_suspicious_keywords,
            self.check_suspicious_tld,
            self.check_domain_age_heuristic,
            self.check_redirects,
            self.check_ssl_certificate,
        ]

        results = []
        total_risk_score = 0

        for rule in rules:
            triggered, score, reason = rule()
            if triggered:
                total_risk_score += score
                results.append({'rule': rule.__name__, 'score': score, 'reason': reason, 'flagged': True})
            else:
                results.append({'rule': rule.__name__, 'score': 0, 'reason': reason, 'flagged': False})

        return total_risk_score, results
