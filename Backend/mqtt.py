"""MQTT deep packet inspection heuristics for protocol-level anomaly detection."""


class MQTTDeepInspector:
    """Inspect decoded MQTT headers and payloads for protocol-level anomalies."""

    def inspect_mqtt_packet(
        self,
        topic: str,
        payload_str: str,
        client_id: str,
    ) -> dict | None:
        """Return a detection result when a packet matches known malicious patterns."""
        # Check for unauthorized topics.
        if topic.startswith("$SYS/admin") or "exec" in topic.lower():
            return {
                "rule_id": "MQTT-DPI-01",
                "message": (
                    f"Unauthorized MQTT Admin Topic Access Attempt on {topic} "
                    f"by client {client_id}"
                ),
                "severity": "Critical",
            }

        # Check for command injection payloads.
        suspicious_keywords = [";", "&&", "|", "rm -rf", "<script>"]
        if any(kw in payload_str for kw in suspicious_keywords):
            return {
                "rule_id": "MQTT-DPI-02",
                "message": (
                    f"Command Injection Payload Detected in Topic {topic} "
                    f"from client {client_id}"
                ),
                "severity": "Critical",
            }
        return None

    def supported_rules(self) -> list[str]:
        """Return the set of rule IDs this inspector can emit."""
        return ["MQTT-DPI-01", "MQTT-DPI-02"]


if __name__ == "__main__":
    inspector = MQTTDeepInspector()
    print(inspector.inspect_mqtt_packet("sensors/temp", "payload; rm -rf /", "client_102"))
