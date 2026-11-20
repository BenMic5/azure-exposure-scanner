"""End-to-end tests of scan.py: exit codes, flags, and error handling."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "scan.py"), *args],
                          capture_output=True, text=True, cwd=ROOT)


class Cli(unittest.TestCase):
    def test_demo_exits_1_and_shows_finding_first(self):
        r = run()
        self.assertEqual(r.returncode, 1)
        first_result = next(line for line in r.stdout.splitlines() if line.startswith("["))
        self.assertEqual(first_result, "[EXPOSED] vm-exposed-ssh: 22/tcp (SSH)")

    def test_real_azure_export_matches_ip_flow_verify(self):
        # Exported from a live subscription; Network Watcher IP flow verify answered Allow via default-allow-ssh.
        r = run("fixtures/live-azure.json")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[EXPOSED] vm-exposed-ssh: 22/tcp (SSH)", r.stdout)
        self.assertIn("rule 'default-allow-ssh' (priority 1000)", r.stdout)

    def test_exits_0_when_nothing_is_exposed(self):
        self.assertEqual(run("--ports", "3389").returncode, 0)

    def test_json_output(self):
        findings = json.loads(run("--json").stdout)
        self.assertEqual(findings[0]["status"], "EXPOSED")
        self.assertEqual(len({f["resource_name"] for f in findings}), 6)

    def test_duplicate_ports_are_scanned_once(self):
        r = run("--ports", "22,22")
        self.assertIn("open TCP to 22 on each VM", r.stdout)
        self.assertEqual(r.stdout.count("[EXPOSED] vm-exposed-ssh"), 1)

    def test_bad_ports_exit_2_with_usage_message(self):
        for value in ("ssh", "0", "70000", ","):
            r = run("--ports", value)
            self.assertEqual(r.returncode, 2, value)
            self.assertIn("--ports", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_unreadable_inventory_exits_2_without_traceback(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not json")
        try:
            for path in ("does-not-exist.json", f.name):
                r = run(path)
                self.assertEqual(r.returncode, 2, path)
                self.assertIn("error: cannot load inventory", r.stderr)
                self.assertNotIn("Traceback", r.stderr)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
