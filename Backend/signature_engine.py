"""Rule-based detection engine for matching suspicious packet signatures."""


class SignatureDetectionEngine:
    """Check incoming packets against known IoT security signature rules."""

    def __init__(self):
        # Known signatures: (Protocol, Target Port) -> Alert details
        self.signatures = {
            ('tcp', 23): {
                'rule_id': 'SIG-101',
                'msg': 'Telnet Connection Attempt (Unencrypted)',
                'severity': 'Medium',
            },
            ('mqtt', 1883): {
                'rule_id': 'SIG-102',
                'msg': 'Unencrypted MQTT Traffic Detected',
                'severity': 'Low',
            },
        }

    def inspect(self, packet: dict) -> dict:
        """Return a detection alert if the packet matches a known signature."""
        key = (packet.get('protocol', '').lower(), packet.get('src_port'))
        if key in self.signatures:
            rule = self.signatures[key]
            return {
                'rule_id': rule['rule_id'],
                'message': rule['msg'],
                'severity': rule['severity'],
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip')
            }

        if packet.get('length', 0) > 400 and packet.get('protocol') == 'udp':
            return {
                'rule_id': 'SIG-103',
                'message': 'Potential UDP Flood / Oversized Payload',
                'severity': 'High',
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip')
            }
        return None

    def has_known_signature(self, packet: dict) -> bool:
        """Return True when a packet matches a configured signature."""
        key = (packet.get('protocol', '').lower(), packet.get('src_port'))
        return key in self.signatures
