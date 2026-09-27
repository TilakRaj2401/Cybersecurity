"""Rule-based detection engine for matching suspicious packet signatures."""


class SignatureDetectionEngine:
    """Check incoming packets against known IoT security signature rules."""

    def __init__(self):
        # Known signatures: (protocol, service port) -> alert details.
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
            ('tcp', 21): {'rule_id': 'SIG-104', 'msg': 'FTP Service Connection Attempt', 'severity': 'Medium'},
            ('tcp', 22): {'rule_id': 'SIG-105', 'msg': 'SSH Service Connection Attempt', 'severity': 'Low'},
            ('tcp', 25): {'rule_id': 'SIG-106', 'msg': 'SMTP Service Connection Attempt', 'severity': 'Low'},
            ('udp', 53): {'rule_id': 'SIG-108', 'msg': 'DNS Query Traffic Detected', 'severity': 'Low'},
            ('tcp', 80): {'rule_id': 'SIG-109', 'msg': 'Unencrypted HTTP Traffic Detected', 'severity': 'Low'},
            ('tcp', 110): {'rule_id': 'SIG-110', 'msg': 'POP3 Cleartext Mail Traffic Detected', 'severity': 'Medium'},
            ('tcp', 135): {'rule_id': 'SIG-112', 'msg': 'MSRPC Service Connection Attempt', 'severity': 'High'},
            ('udp', 137): {'rule_id': 'SIG-113', 'msg': 'NetBIOS Name Service Traffic Detected', 'severity': 'Medium'},
            ('udp', 138): {'rule_id': 'SIG-114', 'msg': 'NetBIOS Datagram Service Traffic Detected', 'severity': 'Medium'},
            ('tcp', 139): {'rule_id': 'SIG-115', 'msg': 'NetBIOS Session Service Traffic Detected', 'severity': 'High'},
            ('tcp', 143): {'rule_id': 'SIG-116', 'msg': 'IMAP Cleartext Mail Traffic Detected', 'severity': 'Medium'},
            ('udp', 161): {'rule_id': 'SIG-117', 'msg': 'SNMP Service Traffic Detected', 'severity': 'Medium'},
            ('tcp', 389): {'rule_id': 'SIG-118', 'msg': 'LDAP Cleartext Directory Traffic Detected', 'severity': 'Medium'},
            ('tcp', 443): {'rule_id': 'SIG-119', 'msg': 'HTTPS Service Traffic Detected', 'severity': 'Low'},
            ('tcp', 445): {'rule_id': 'SIG-120', 'msg': 'SMB File Sharing Traffic Detected', 'severity': 'High'},
            ('tcp', 502): {'rule_id': 'SIG-121', 'msg': 'Modbus TCP Industrial Protocol Detected', 'severity': 'Critical'},
            ('udp', 500): {'rule_id': 'SIG-122', 'msg': 'IKE VPN Negotiation Traffic Detected', 'severity': 'Low'},
            ('udp', 123): {'rule_id': 'SIG-123', 'msg': 'NTP Service Traffic Detected', 'severity': 'Low'},
            ('udp', 1900): {'rule_id': 'SIG-124', 'msg': 'UPnP SSDP Discovery Traffic Detected', 'severity': 'Medium'},
            ('tcp', 2323): {'rule_id': 'SIG-125', 'msg': 'Alternative Telnet Port Detected', 'severity': 'High'},
            ('tcp', 3389): {'rule_id': 'SIG-126', 'msg': 'Remote Desktop Protocol Traffic Detected', 'severity': 'High'},
            ('tcp', 4444): {'rule_id': 'SIG-127', 'msg': 'Common Remote Shell Port Detected', 'severity': 'Critical'},
            ('udp', 4500): {'rule_id': 'SIG-128', 'msg': 'IPsec NAT Traversal Traffic Detected', 'severity': 'Low'},
            ('tcp', 4840): {'rule_id': 'SIG-129', 'msg': 'OPC UA Industrial Protocol Detected', 'severity': 'Critical'},
            ('udp', 5683): {'rule_id': 'SIG-130', 'msg': 'Unencrypted CoAP Traffic Detected', 'severity': 'Medium'},
            ('tcp', 5900): {'rule_id': 'SIG-131', 'msg': 'VNC Remote Access Traffic Detected', 'severity': 'High'},
            ('tcp', 8080): {'rule_id': 'SIG-132', 'msg': 'Alternative HTTP Proxy Traffic Detected', 'severity': 'Medium'},
            ('udp', 47808): {'rule_id': 'SIG-133', 'msg': 'BACnet Building Automation Traffic Detected', 'severity': 'Critical'},
        }

    def inspect(self, packet: dict) -> dict:
        """Return a detection alert if the packet matches a known signature."""
        protocol = str(packet.get('protocol', '')).lower()
        ports = (packet.get('src_port'), packet.get('dst_port'))
        rule = next(
            (self.signatures[(protocol, port)] for port in ports if (protocol, port) in self.signatures),
            None,
        )
        if rule:
            return {
                'rule_id': rule['rule_id'],
                'message': rule['msg'],
                'severity': rule['severity'],
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip')
            }

        if packet.get('length', 0) > 400 and protocol == 'udp':
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
        protocol = str(packet.get('protocol', '')).lower()
        return any((protocol, port) in self.signatures for port in (packet.get('src_port'), packet.get('dst_port')))
