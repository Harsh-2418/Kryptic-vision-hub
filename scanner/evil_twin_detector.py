class EvilTwinDetector:
    """
    Simulated Evil Twin Attack Detection Engine.
    Compares active access point parameters (SSID, BSSID, Channel, Encryption, Frequency) against trusted profiles.
    Does NOT require administrator access or physical packet capture.
    """

    @staticmethod
    def analyze_access_point(current_ssid, current_bssid, current_channel=None, current_encryption=None, current_frequency=None,
                             trusted_ssid=None, trusted_bssid=None, trusted_channel=None, trusted_encryption=None, trusted_frequency=None):
        
        if not current_ssid or not current_bssid:
            return {
                'success': False,
                'error': 'Current SSID and BSSID (MAC Address) are required.'
            }

        risk_score = 0
        triggered_rules = []

        c_ssid = current_ssid.strip()
        c_bssid = current_bssid.strip().lower()
        c_enc = (current_encryption or '').upper()

        t_ssid = (trusted_ssid or '').strip()
        t_bssid = (trusted_bssid or '').strip().lower()
        t_enc = (trusted_encryption or '').upper()

        # Rule 1: Same SSID, Different BSSID (+40)
        if t_ssid and c_ssid.lower() == t_ssid.lower() and t_bssid and c_bssid != t_bssid:
            risk_score += 40
            triggered_rules.append({
                'rule': 'Same SSID with Different BSSID (MAC Mismatch)',
                'score': 40,
                'detail': f'Access point advertises trusted SSID "{c_ssid}" but has BSSID {c_bssid} instead of expected {t_bssid}.'
            })

        # Rule 2: Different Encryption vs Trusted Profile (+20)
        if t_enc and c_enc != t_enc:
            risk_score += 20
            triggered_rules.append({
                'rule': 'Different Encryption Profile',
                'score': 20,
                'detail': f'Current encryption ({current_encryption}) differs from trusted profile ({trusted_encryption}).'
            })

        # Rule 3: Different Channel vs Trusted Profile (+10)
        if trusted_channel and current_channel and str(current_channel) != str(trusted_channel):
            risk_score += 10
            triggered_rules.append({
                'rule': 'Different Broadcast Channel',
                'score': 10,
                'detail': f'Broadcasting on channel {current_channel} instead of expected channel {trusted_channel}.'
            })

        # Rule 4: Different Frequency Band (+10)
        if trusted_frequency and current_frequency and str(current_frequency) != str(trusted_frequency):
            risk_score += 10
            triggered_rules.append({
                'rule': 'Different Frequency Band',
                'score': 10,
                'detail': f'Operating on frequency band {current_frequency} instead of {trusted_frequency}.'
            })

        # Rule 5: Weak Encryption Standard (+20)
        if c_enc in ['OPEN', 'NONE', 'WEP', 'UNENCRYPTED']:
            risk_score += 20
            triggered_rules.append({
                'rule': 'Weak / Degraded Security Standard',
                'score': 20,
                'detail': f'Current network utilizes weak or missing encryption ({current_encryption}).'
            })

        risk_score = min(risk_score, 100)

        if risk_score <= 25:
            status = "Safe Network"
            status_class = "success"
            recommendation = "Access point parameters align with trusted profile metrics."
        elif risk_score <= 50:
            status = "Suspicious Network"
            status_class = "warning"
            recommendation = "Minor configuration discrepancies detected. Confirm access point authenticity before logging in."
        else:
            status = "Possible Evil Twin Attack"
            status_class = "danger"
            recommendation = "CRITICAL RISK! High probability of a rogue Evil Twin access point spoofing a legitimate network. Disconnect immediately."

        return {
            'success': True,
            'ssid': c_ssid,
            'bssid': c_bssid,
            'channel': current_channel,
            'encryption': current_encryption,
            'frequency': current_frequency,
            'risk_score': risk_score,
            'status': status,
            'status_class': status_class,
            'triggered_rules': triggered_rules,
            'recommendation': recommendation
        }
