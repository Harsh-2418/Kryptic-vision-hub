import re
from urllib.parse import urlparse

class URLValidator:
    @staticmethod
    def normalize_url(url_string):
        if not url_string:
            return ""
        url_string = url_string.strip()
        if not re.match(r'^https?://', url_string, re.IGNORECASE):
            url_string = 'http://' + url_string
        return url_string

    @staticmethod
    def is_valid_url(url_string):
        if not url_string:
            return False, "URL cannot be empty."
        
        normalized = URLValidator.normalize_url(url_string)
        try:
            parsed = urlparse(normalized)
            hostname = parsed.hostname
            if not hostname:
                return False, "Invalid URL structure or domain missing."
            
            # Allow IP addresses or valid domain format
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            
            if not (re.match(ip_pattern, hostname) or re.match(domain_pattern, hostname) or hostname == 'localhost'):
                return False, "Invalid hostname format."
                
            return True, normalized
        except Exception as e:
            return False, f"URL parsing error: {str(e)}"
