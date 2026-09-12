import tempfile
import unittest
from pathlib import Path

from workflow_auditor.auditor import AuditError, audit_file, audit_paths


PINNED_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def write_workflow(directory: str, content: str) -> Path:
    path = Path(directory) / "workflow.yml"
    path.write_text(content, encoding="utf-8")
    return path


class AuditorTests(unittest.TestCase):
    def test_secure_workflow_has_no_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                f"""
on: push
permissions:
  contents: read
concurrency:
  group: test
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: {PINNED_CHECKOUT}
      - run: python -m unittest
""",
            )

            self.assertEqual([], audit_file(path))

    def test_missing_permissions_is_high(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                """
on: push
concurrency: test
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
""",
            )

            findings = audit_file(path)
            self.assertTrue(
                any(
                    finding.rule_id == "GHA001" and finding.severity == "high"
                    for finding in findings
                )
            )

    def test_mutable_action_reference_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                """
on: push
permissions:
  contents: read
concurrency: test
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
""",
            )

            self.assertTrue(
                any(finding.rule_id == "GHA005" for finding in audit_file(path))
            )

    def test_direct_event_interpolation_is_high(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                """
on: pull_request
permissions:
  contents: read
concurrency: test
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
""",
            )

            findings = audit_file(path)
            self.assertTrue(
                any(
                    finding.rule_id == "GHA006" and finding.severity == "high"
                    for finding in findings
                )
            )

    def test_pull_request_target_head_checkout_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                """
on: pull_request_target
permissions:
  contents: write
concurrency: test
jobs:
  review:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""",
            )

            rules = {finding.rule_id for finding in audit_file(path)}
            self.assertIn("GHA007", rules)
            self.assertIn("GHA010", rules)

    def test_oidc_without_environment_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                """
on: push
permissions:
  contents: read
concurrency: deploy
jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      id-token: write
""",
            )

            self.assertTrue(
                any(finding.rule_id == "GHA008" for finding in audit_file(path))
            )

    def test_reusable_workflow_secret_inheritance_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(
                directory,
                """
on: push
permissions:
  contents: read
concurrency: call
jobs:
  call:
    uses: example/reusable/.github/workflows/build.yml@main
    secrets: inherit
""",
            )

            self.assertTrue(
                any(finding.rule_id == "GHA009" for finding in audit_file(path))
            )

    def test_invalid_yaml_raises_audit_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_workflow(directory, "jobs: [")

            with self.assertRaisesRegex(AuditError, "invalid YAML"):
                audit_file(path)

    def test_directory_discovery_scans_yaml_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ".github" / "workflows"
            root.mkdir(parents=True)
            (root / "one.yml").write_text(
                "on: push\npermissions: read-all\nconcurrency: x\njobs: {}\n",
                encoding="utf-8",
            )
            (root / "two.yaml").write_text(
                "on: push\npermissions: read-all\nconcurrency: x\njobs: {}\n",
                encoding="utf-8",
            )

            self.assertEqual(2, audit_paths([Path(directory)]).files_scanned)


if __name__ == "__main__":
    unittest.main()
