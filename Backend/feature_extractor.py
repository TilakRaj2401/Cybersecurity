"""Utilities for converting raw IoT packet data into a numeric feature vector."""

import numpy as np

def extract_iot_features(raw_packet_data: dict) -> np.ndarray:
    """Extracts numerical feature vector from raw network packet stream for ML processing."""
    proto_map = {'tcp': 1, 'udp': 2, 'mqtt': 3, 'coap': 4}

    proto = proto_map.get(raw_packet_data.get('protocol', '').lower(), 0)
    pkt_len = float(raw_packet_data.get('length', 0))
    src_port = float(raw_packet_data.get('src_port', 0))
    dst_port = float(raw_packet_data.get('dst_port', 0))
    flow_duration = float(raw_packet_data.get('duration', 0.0))
    payload_entropy = float(raw_packet_data.get('entropy', 0.0))

    return np.array(
        [[proto, pkt_len, src_port, dst_port, flow_duration, payload_entropy]],
        dtype=np.float32,
    )

if __name__ == '__main__':
    sample = {
        'protocol': 'mqtt',
        'length': 128,
        'src_port': 1883,
        'dst_port': 45120,
        'duration': 0.045,
        'entropy': 3.4,
    }
    print("Extracted Features:", extract_iot_features(sample))
