import unittest
from src.iot_analyzer import analyze, summarize


class IoTAnalyzerTests(unittest.TestCase):
    def test_secure_device_has_no_findings(self):
        device = {"device_id":"sensor-1","firmware_supported":True,"management_protocols":["https"],"default_or_shared_credentials":False,"segmented":True,"telemetry_encrypted":True,"automatic_updates":True}
        self.assertEqual(analyze([device]), [])

    def test_telnet_is_critical(self):
        device = {"device_id":"camera-1","firmware_supported":True,"management_protocols":["telnet"],"default_or_shared_credentials":False,"segmented":True,"telemetry_encrypted":True,"automatic_updates":True}
        findings = analyze([device])
        self.assertTrue(any(f.control_id == "IOT-002" and f.severity == "critical" for f in findings))

    def test_default_credentials_are_critical(self):
        device = {"device_id":"camera-2","firmware_supported":True,"management_protocols":["https"],"default_or_shared_credentials":True,"segmented":True,"telemetry_encrypted":True,"automatic_updates":True}
        findings = analyze([device])
        self.assertTrue(any(f.control_id == "IOT-003" for f in findings))

    def test_multiple_controls_are_counted(self):
        device = {"device_id":"gateway-1","firmware_supported":False,"management_protocols":["http"],"default_or_shared_credentials":False,"segmented":False,"telemetry_encrypted":False,"automatic_updates":False}
        summary = summarize(analyze([device]))
        self.assertEqual(summary["critical"], 1)
        self.assertGreaterEqual(summary["high"], 3)
        self.assertEqual(summary["medium"], 1)


if __name__ == "__main__":
    unittest.main()
