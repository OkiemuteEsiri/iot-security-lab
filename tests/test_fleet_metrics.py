import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "fleet_metrics.py"
spec = importlib.util.spec_from_file_location("fleet_metrics", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class FleetMetricsTests(unittest.TestCase):
    def test_empty_fleet_is_safe(self):
        metrics = module.calculate_fleet_metrics([], [])
        self.assertEqual(metrics["total_devices"], 0)
        self.assertEqual(metrics["affected_device_percentage"], 0.0)

    def test_metrics_count_unique_affected_devices(self):
        devices = [{"device_id": "a"}, {"device_id": "b"}, {"device_id": "c"}]
        findings = [
            SimpleNamespace(device_id="a", severity="critical"),
            SimpleNamespace(device_id="a", severity="high"),
            SimpleNamespace(device_id="b", severity="medium"),
        ]
        metrics = module.calculate_fleet_metrics(devices, findings)
        self.assertEqual(metrics["affected_devices"], 2)
        self.assertEqual(metrics["affected_device_percentage"], 66.7)
        self.assertEqual(metrics["findings_by_severity"]["critical"], 1)

    def test_critical_finding_drives_immediate_priority(self):
        metrics = {"findings_by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0}}
        self.assertEqual(module.remediation_priority(metrics), "immediate")

    def test_three_high_findings_drive_accelerated_priority(self):
        metrics = {"findings_by_severity": {"critical": 0, "high": 3, "medium": 0, "low": 0}}
        self.assertEqual(module.remediation_priority(metrics), "accelerated")


if __name__ == "__main__":
    unittest.main()
