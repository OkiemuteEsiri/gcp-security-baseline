import unittest

from src.assessor import assess_inventory, summarize
from src.controls import CONTROLS


class GcpBaselineTests(unittest.TestCase):
    def test_public_bucket_is_high(self):
        result = assess_inventory([{"type":"storage_bucket","name":"b","project_id":"p","public":True,"uniform_bucket_level_access":True}])
        self.assertTrue(any(f.control_id == "GCP-STO-001" and f.severity == "high" for f in result.findings))

    def test_private_bucket_with_uniform_access_has_no_storage_findings(self):
        result = assess_inventory([{"type":"storage_bucket","name":"b","project_id":"p","public":False,"uniform_bucket_level_access":True}])
        self.assertFalse(result.findings)

    def test_multiple_service_account_keys_raise_high(self):
        result = assess_inventory([{"type":"service_account","name":"sa","project_id":"p","user_managed_keys":2}])
        self.assertEqual(result.findings[0].severity, "high")

    def test_external_admin_is_critical(self):
        result = assess_inventory([{"type":"iam_binding","name":"admins","project_id":"p","role":"roles/owner","members":["user:x@outside.example"],"approved_domains":["@corp.example"]}])
        self.assertTrue(any(f.control_id == "GCP-IAM-003" and f.severity == "critical" for f in result.findings))

    def test_open_ssh_firewall_is_critical(self):
        result = assess_inventory([{"type":"firewall_rule","name":"ssh","project_id":"p","source_ranges":["0.0.0.0/0"],"allowed_ports":[22]}])
        self.assertEqual(result.findings[0].control_id, "GCP-NET-001")
        self.assertEqual(result.findings[0].severity, "critical")

    def test_private_cloud_sql_has_no_finding(self):
        result = assess_inventory([{"type":"cloud_sql","name":"db","project_id":"p","public_ip":False,"authorized_networks":[]}])
        self.assertFalse(result.findings)

    def test_logging_data_access_gap_is_medium(self):
        result = assess_inventory([{"type":"project_logging","name":"logs","project_id":"p","admin_activity":True,"data_access":False,"sink_enabled":True}])
        self.assertEqual(result.findings[0].severity, "medium")

    def test_summary_score_is_bounded(self):
        result = assess_inventory([{"type":"firewall_rule","name":"ssh","project_id":"p","source_ranges":["0.0.0.0/0"],"allowed_ports":[22]}])
        score = summarize(result)["posture_score"]
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_missing_required_field_fails_closed(self):
        with self.assertRaises(ValueError):
            assess_inventory([{"type":"storage_bucket","name":"b","project_id":"p","public":True}])

    def test_control_catalog_has_expected_depth(self):
        self.assertGreaterEqual(len(CONTROLS), 8)


if __name__ == "__main__":
    unittest.main()
