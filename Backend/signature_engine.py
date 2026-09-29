"""Rule-based detection engine for matching suspicious packet signatures."""

from __future__ import annotations

import json
from pathlib import Path


class SignatureDetectionEngine:
    """Check incoming packets against known IoT security signature rules."""

    LEGACY_DATASET_RULES = {
        'KDDCup99': {
            'dos': {
                'rule_id': 'SIG-300',
                'message': 'DoS attack family from legacy KDD Cup 99 traffic',
                'severity': 'High',
            },
            'probe': {
                'rule_id': 'SIG-301',
                'message': 'Probe/scan activity from legacy IDS datasets',
                'severity': 'Medium',
            },
            'u2r': {
                'rule_id': 'SIG-302',
                'message': 'User-to-root exploit family',
                'severity': 'Critical',
            },
            'r2l': {
                'rule_id': 'SIG-303',
                'message': 'Remote-to-local intrusion family',
                'severity': 'High',
            },
        },
        'NSL-KDD': {
            'dos': {
                'rule_id': 'SIG-300',
                'message': 'DoS attack family from legacy NSL-KDD traffic',
                'severity': 'High',
            },
            'probe': {
                'rule_id': 'SIG-301',
                'message': 'Probe activity from legacy NSL-KDD traffic',
                'severity': 'Medium',
            },
            'u2r': {
                'rule_id': 'SIG-302',
                'message': 'User-to-root exploit family',
                'severity': 'Critical',
            },
            'r2l': {
                'rule_id': 'SIG-303',
                'message': 'Remote-to-local attack family',
                'severity': 'High',
            },
        },
        'UNSW-NB15': {
            'analysis': {
                'rule_id': 'SIG-304',
                'message': 'Analysis attack family from UNSW-NB15',
                'severity': 'Medium',
            },
            'backdoor': {
                'rule_id': 'SIG-305',
                'message': 'Backdoor behavior in UNSW-NB15 traffic',
                'severity': 'Critical',
            },
            'dos': {
                'rule_id': 'SIG-300',
                'message': 'DoS activity in UNSW-NB15 traffic',
                'severity': 'High',
            },
            'reconnaissance': {
                'rule_id': 'SIG-301',
                'message': 'Reconnaissance traffic seen in UNSW-NB15',
                'severity': 'Medium',
            },
            'worms': {
                'rule_id': 'SIG-306',
                'message': 'Worm propagation signature',
                'severity': 'Critical',
            },
        },
    }

    def __init__(self, signature_file: str | Path | None = None):
        self.default_signature_file = (
            Path(signature_file) if signature_file else Path(__file__).with_name('sig.json')
        )
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
            ('tcp', 21): {'rule_id': 'SIG-104',
             'msg': 'FTP Service Connection Attempt',
              'severity': 'Medium'},
            ('tcp', 22): {'rule_id': 'SIG-105',
             'msg': 'SSH Service Connection Attempt',
              'severity': 'Low'},
            ('tcp', 25): {'rule_id': 'SIG-106',
             'msg': 'SMTP Service Connection Attempt',
              'severity': 'Low'},
            ('udp', 53): {'rule_id': 'SIG-108',
             'msg': 'DNS Query Traffic Detected',
              'severity': 'Low'},
            ('tcp', 80): {'rule_id': 'SIG-109',
             'msg': 'Unencrypted HTTP Traffic Detected',
              'severity': 'Low'},
            ('tcp', 110): {'rule_id': 'SIG-110',
             'msg': 'POP3 Cleartext Mail Traffic Detected',
              'severity': 'Medium'},
            ('tcp', 135): {'rule_id': 'SIG-112',
             'msg': 'MSRPC Service Connection Attempt',
              'severity': 'High'},
            ('udp', 137): {'rule_id': 'SIG-113',
             'msg': 'NetBIOS Name Service Traffic Detected',
              'severity': 'Medium'},
            ('udp', 138): {'rule_id': 'SIG-114',
             'msg': 'NetBIOS Datagram Service Traffic Detected',
              'severity': 'Medium'},
            ('tcp', 139): {'rule_id': 'SIG-115',
             'msg': 'NetBIOS Session Service Traffic Detected', 'severity': 'High'},
            ('tcp', 143): {'rule_id': 'SIG-116',
             'msg': 'IMAP Cleartext Mail Traffic Detected',
              'severity': 'Medium'},
            ('udp', 161): {'rule_id': 'SIG-117',
             'msg': 'SNMP Service Traffic Detected',
              'severity': 'Medium'},
            ('tcp', 389): {'rule_id': 'SIG-118',
             'msg': 'LDAP Cleartext Directory Traffic Detected',
              'severity': 'Medium'},
            ('tcp', 443): {'rule_id': 'SIG-119',
             'msg': 'HTTPS Service Traffic Detected',
              'severity': 'Low'},
            ('tcp', 445): {'rule_id': 'SIG-120',
             'msg': 'SMB File Sharing Traffic Detected',
              'severity': 'High'},
            ('tcp', 502): {'rule_id': 'SIG-121',
             'msg': 'Modbus TCP Industrial Protocol Detected',
              'severity': 'Critical'},
            ('udp', 500): {'rule_id': 'SIG-122',
             'msg': 'IKE VPN Negotiation Traffic Detected',
              'severity': 'Low'},
            ('udp', 123): {'rule_id': 'SIG-123',
             'msg': 'NTP Service Traffic Detected',
              'severity': 'Low'},
            ('udp', 1900): {'rule_id': 'SIG-124',
             'msg': 'UPnP SSDP Discovery Traffic Detected',
              'severity': 'Medium'},
            ('tcp', 2323): {'rule_id': 'SIG-125',
             'msg': 'Alternative Telnet Port Detected',
              'severity': 'High'},
            ('tcp', 3389): {'rule_id': 'SIG-126',
             'msg': 'Remote Desktop Protocol Traffic Detected',
              'severity': 'High'},
            ('tcp', 4444): {'rule_id': 'SIG-127',
             'msg': 'Common Remote Shell Port Detected',
              'severity': 'Critical'},
            ('udp', 4500): {'rule_id': 'SIG-128',
             'msg': 'IPsec NAT Traversal Traffic Detected',
              'severity': 'Low'},
            ('tcp', 4840): {'rule_id': 'SIG-129',
             'msg': 'OPC UA Industrial Protocol Detected',
              'severity': 'Critical'},
            ('udp', 5683): {'rule_id': 'SIG-130',
             'msg': 'Unencrypted CoAP Traffic Detected',
              'severity': 'Medium'},
            ('tcp', 5900): {'rule_id': 'SIG-131',
             'msg': 'VNC Remote Access Traffic Detected',
              'severity': 'High'},
            ('tcp', 8080): {'rule_id': 'SIG-132',
             'msg': 'Alternative HTTP Proxy Traffic Detected',
              'severity': 'Medium'},
            ('udp', 47808): {'rule_id': 'SIG-133',
             'msg': 'BACnet Building Automation Traffic Detected',
              'severity': 'Critical'},
        }
        self.load_rules_from_file(self.default_signature_file)
        self.payload_signatures = [
            {
                'rule_id': 'SIG-200',
                'message': 'Telnet credential or login sequence detected',
                'severity': 'High',
                'keywords': (
                    'telnet', 'login', 'root', 'admin', 'password', 'username'
                ),
            },
            {
                'rule_id': 'SIG-201',
                'message': 'MQTT command or broker interaction detected',
                'severity': 'Medium',
                'keywords': (
                    'mqtt', 'connect', 'publish', 'subscribe', 'broker',
                    'client id',
                ),
            },
            {
                'rule_id': 'SIG-202',
                'message': 'Suspicious remote shell activity detected',
                'severity': 'Critical',
                'keywords': (
                    'nc -e', 'bash -i', 'powershell', 'cmd.exe',
                    'wget http', 'curl http',
                ),
            },
        ]

    def load_rules_from_file(self, file_path: str | Path):
        """Load signature rules from a JSON file and normalize them to tuple keys."""
        path = Path(file_path)
        if not path.exists():
            return self.signatures

        with path.open('r', encoding='utf-8') as handle:
            raw_rules = json.load(handle)

        parsed_rules = {}
        for key, rule in raw_rules.items():
            protocol, port_text = key.split(':', 1)
            parsed_rules[(protocol.lower(), int(port_text))] = {
                'rule_id': rule['rule_id'],
                'msg': rule['msg'],
                'severity': rule['severity'],
            }

        self.signatures = parsed_rules
        return self.signatures

    @classmethod
    def load_legacy_dataset_rules(cls, dataset_name: str = 'NSL-KDD') -> dict:
        """Return canonical attack-family signatures from public legacy IDS datasets."""
        if dataset_name not in cls.LEGACY_DATASET_RULES:
            raise ValueError(
                f"Unsupported dataset '{dataset_name}'. "
                f"Available datasets: {', '.join(cls.LEGACY_DATASET_RULES)}"
            )
        return cls.LEGACY_DATASET_RULES[dataset_name]

    def apply_legacy_dataset_rules(self, dataset_name: str = 'NSL-KDD'):
        """Add dataset-derived attack-family rules to the payload matcher."""
        dataset_rules = self.load_legacy_dataset_rules(dataset_name)
        for family, details in dataset_rules.items():
            self.payload_signatures.append({
                'rule_id': details['rule_id'],
                'message': details['message'],
                'severity': details['severity'],
                'keywords': (family, 'attack', 'malware', 'scan', 'flood', 'exploit'),
            })

    def _check_payload_signatures(self, packet: dict) -> dict | None:
        """Return a detection alert if the packet payload matches a known suspicious pattern."""
        payload = str(packet.get('payload', '') or packet.get('data', '') or '').lower()
        if not payload:
            return None

        for signature in self.payload_signatures:
            if any(keyword in payload for keyword in signature['keywords']):
                return {
                    'rule_id': signature['rule_id'],
                    'message': signature['message'],
                    'severity': signature['severity'],
                    'src_ip': packet.get('src_ip'),
                    'dst_ip': packet.get('dst_ip'),
                }
        return None

    def inspect(self, packet: dict) -> dict:
        """Return a detection alert if the packet matches a known signature."""
        payload_match = self._check_payload_signatures(packet)
        if payload_match:
            return payload_match

        protocol = str(packet.get('protocol', '')).lower()
        ports = (packet.get('src_port'), packet.get('dst_port'))
        rule = next(
            (self.signatures[(protocol, port)]
            for port in ports
            if (protocol, port)
            in self.signatures),
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
        if self._check_payload_signatures(packet) is not None:
            return True

        protocol = str(packet.get('protocol', '')).lower()
        return any((protocol, port) in self.signatures
        for port in (packet.get('src_port'), packet.get('dst_port')))
