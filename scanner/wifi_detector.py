class WiFiDetector:
    """
    Simulated Wireless Security Configuration Analyzer.
    Evaluates network parameters against baseline rules and trusted network profiles.
    Does NOT require WiFi hardware or admin privileges.
    """

    @staticmethod
    def analyze_network(ssid, encryption, signal_strength=None, channel=None, frequency=None, trusted_ssid=None, trusted_encryption=None, trusted_channel=None):
        if not ssid or not ssid.strip():
            return {
                'success': False,
                'error': 'SSID is required.'
            }

        risk_score = 0
        triggered_rules = []
        enc_upper = (encryption or '').upper()

        # Rule 1: Open / Unencrypted Network (+40)
        if enc_upper in ['OPEN', 'NONE', 'UNENCRYPTED']:
            risk_score += 40
            triggered_rules.append({'rule': 'Unencrypted / Open Network', 'score': 40, 'detail': 'Network offers no encryption; data transmitted in cleartext.'})
        # Rule 2: Legacy WEP Encryption (+30)
        elif 'WEP' in enc_upper:
            risk_score += 30
            triggered_rules.append({'rule': 'Weak Encryption (WEP)', 'score': 30, 'detail': 'WEP encryption protocol is deprecated and vulnerable to instant key extraction.'})

        # Rule 3: Weak Signal Strength (+10)
        if signal_strength:
            try:
                sig = int(signal_strength)
                if sig < -80:
                    risk_score += 10
                    triggered_rules.append({'rule': 'Weak Signal Strength', 'score': 10, 'detail': f'Signal strength ({sig} dBm) is unusually weak for a legitimate access point.'})
            except ValueError:
                pass

        # Comparison with Trusted Network Profile
        if trusted_ssid and trusted_ssid.strip().lower() == ssid.strip().lower():
            # Rule 4: Trusted SSID with changed security (+30)
            if trusted_encryption and enc_upper != trusted_encryption.upper():
                risk_score += 30
                triggered_rules.append({'rule': 'SSID Matches Trusted but Security Differs', 'score': 30, 'detail': f'Target SSID matches "{trusted_ssid}" but encryption changed from {trusted_encryption} to {encryption}.'})
            # Rule 5: Different Encryption vs Trusted (+20)
            elif trusted_encryption and enc_upper != trusted_encryption.upper():
                risk_score += 20
                triggered_rules.append({'rule': 'Different Encryption than Trusted', 'score': 20, 'detail': 'Encryption type does not match trusted profile.'})

            # Rule 6: Different Channel vs Trusted (+10)
            if trusted_channel and channel and str(channel) != str(trusted_channel):
                risk_score += 10
                triggered_rules.append({'rule': 'Different Channel than Trusted Profile', 'score': 10, 'detail': f'Operating on channel {channel} instead of expected channel {trusted_channel}.'})

        risk_score = min(risk_score, 100)

        if risk_score <= 25:
            status = "Safe Network"
            status_class = "success"
            recommendation = "This wireless network configuration meets expected security baseline requirements."
        elif risk_score <= 50:
            status = "Suspicious Network"
            status_class = "warning"
            recommendation = "Exercise caution before connecting. Verify access point credentials and avoid transmitting unencrypted data."
        else:
            status = "Possible Fake WiFi / High Threat Network"
            status_class = "danger"
            recommendation = "Do not connect! Network parameters indicate a potential rouge access point or unencrypted honeypot."

        return {
            'success': True,
            'ssid': ssid,
            'encryption': encryption,
            'signal_strength': signal_strength,
            'channel': channel,
            'frequency': frequency,
            'risk_score': risk_score,
            'status': status,
            'status_class': status_class,
            'triggered_rules': triggered_rules,
            'recommendation': recommendation
        }
