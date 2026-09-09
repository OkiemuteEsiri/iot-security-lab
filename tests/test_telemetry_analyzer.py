import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "telemetry_analyzer.py"
spec = importlib.util.spec_from_file_location("telemetry_analyzer", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class TelemetryAnalyzerTests(unittest.TestCase):
    def test_unapproved_plaintext_mqtt_creates_two_findings(self):
        findings = module.analyze_telemetry([{
            "device_id": "cam-1", "event_type": "network_connection",
            "destination": "203.0.113.10", "destination_approved": False,
            "protocol": "mqtt", "port": 1883,
        }])
        self.assertEqual({finding.rule_id for finding in findings}, {"IOT-T001", "IOT-T002"})

    def test_publish_rate_requires_five_times_baseline(self):
        findings = module.analyze_telemetry([{
            "device_id": "sensor-1", "event_type": "publish_rate",
            "messages_per_minute": 499, "baseline_messages_per_minute": 100,
        }])
        self.assertEqual(findings, [])

    def test_repeated_authentication_failures_trigger_threshold(self):
        events = [
            {"device_id": "gateway-1", "event_type": "authentication", "result": "failure"}
            for _ in range(5)
        ]
        findings = module.analyze_telemetry(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IOT-T004")

    def test_unapproved_broker_is_critical(self):
        findings = module.analyze_telemetry([{
            "device_id": "gateway-2", "event_type": "broker_registration",
            "broker": "shadow.local", "broker_approved": False,
        }])
        self.assertEqual(findings[0].severity, "critical")

    def test_summary_counts_severity(self):
        findings = module.analyze_telemetry([{
            "device_id": "gateway-2", "event_type": "broker_registration",
            "broker": "shadow.local", "broker_approved": False,
        }])
        self.assertEqual(module.summarize(findings)["critical"], 1)


if __name__ == "__main__":
    unittest.main()
