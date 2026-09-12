import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from workflow_auditor.cli import main


class CliTests(unittest.TestCase):
    def test_json_output_and_failure_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text(
                """
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
""",
                encoding="utf-8",
            )
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main([str(path), "--format", "json"])

            payload = json.loads(output.getvalue())
            self.assertEqual(2, exit_code)
            self.assertEqual(1, payload["files_scanned"])
            self.assertGreater(payload["counts"]["critical"], 0)

    def test_fail_on_none_returns_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            path.write_text(
                "on: push\npermissions: write-all\njobs: {}\n",
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([str(path), "--fail-on", "none"]))


if __name__ == "__main__":
    unittest.main()
