"""Simple packet-sniffing mock used to generate network traffic samples for feature extraction."""

import time
import random

class PacketSniffer:
    """Mock/Scapy abstraction layer for non-blocking packet capturing."""

    def __init__(self, interface: str = "eth0"):
        """Initialize the sniffer with the target network interface."""
        self.interface = interface
        self.running = False

    def start_capture(self, callback, max_packets=5):
        """Generate mock packets and pass them to the provided callback."""
        self.running = True
        captured = 0
        protocols = ['tcp', 'udp', 'mqtt', 'coap']

        while self.running and captured < max_packets:
            packet = {
                'src_ip': f"192.168.1.{random.randint(2, 50)}",
                'dst_ip': "192.168.1.1",
                'protocol': random.choice(protocols),
                'length': random.randint(40, 512),
                'src_port': random.choice([1883, 5683, 80, 443]),
                'dst_port': random.randint(1024, 65535),
                'duration': round(random.uniform(0.001, 0.5), 4),
                'entropy': round(random.uniform(0.0, 8.0), 2)
            }
            callback(packet)
            captured += 1
            time.sleep(0.1)

if __name__ == '__main__':
    sniffer = PacketSniffer()
    sniffer.start_capture(lambda p: print("Captured Packet:", p))
