import json
from scanner.url_validator import URLValidator
from scanner.feature_extractor import FeatureExtractor

class PhishingDetector:
    @staticmethod
    def analyze_url(url_string):
        valid, normalized_url_or_err = URLValidator.is_valid_url(url_string)
        if not valid:
            return {
                'success': False,
                'error': normalized_url_or_err
            }

        url = normalized_url_or_err
        extractor = FeatureExtractor(url)
        raw_score, rule_results = extractor.extract_all_features()

        # Cap score between 0 and 100
        risk_score = min(raw_score, 100)

        # Result calculation mapping according to requirements:
        # 0-25: Safe (Green)
        # 26-50: Suspicious (Orange)
        # 51+: Dangerous (Red)
        if risk_score <= 25:
            status = "Safe"
            status_class = "success"
            badge_color = "#16A34A"
            recommendation = "This URL shows low risk characteristics. You can proceed, but stay cautious when entering personal data."
        elif risk_score <= 50:
            status = "Suspicious"
            status_class = "warning"
            badge_color = "#F59E0B"
            recommendation = "Caution advised! This URL exhibits several suspicious traits typical of phishing links. Verify source before proceeding."
        else:
            status = "Dangerous"
            status_class = "danger"
            badge_color = "#DC2626"
            recommendation = "Critical Risk! Avoid visiting this website. Highly probable phishing attempt designed to compromise credentials or security."

        # Filter flagged reasons and safe notes
        flagged_reasons = [item['reason'] for item in rule_results if item['flagged']]
        if not flagged_reasons:
            flagged_reasons = ["HTTPS enabled", "Legitimate domain structure", "No suspicious characters or keywords detected"]

        return {
            'success': True,
            'url': url,
            'risk_score': risk_score,
            'status': status,
            'status_class': status_class,
            'badge_color': badge_color,
            'reasons': flagged_reasons,
            'all_rules': rule_results,
            'recommendation': recommendation
        }
