"""Command-line interface for workflow-audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .auditor import AuditError, AuditResult, SEVERITY_RANK, audit_paths


def render_text(result: AuditResult) -> str:
    counts = result.counts()
    lines = [
        f"Scanned:  {result.files_scanned} workflow file(s)",
        "Findings: "
        + ", ".join(
            f"{counts[severity]} {severity}"
            for severity in ("critical", "high", "medium", "low")
        ),
    ]
    for finding in result.findings:
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.rule_id} {finding.source}",
                f"  Location: {finding.location}",
                f"  {finding.message}",
            ]
        )
    if not result.findings:
        lines.extend(["", "No findings."])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit GitHub Actions workflows for security and reliability risks."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[Path(".")],
        help="workflow files or directories (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="high",
        help="return status 2 at this severity or higher (default: high)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = audit_paths(args.paths)
    except AuditError as error:
        print(f"workflow-audit: {error}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(render_text(result))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    if any(
        SEVERITY_RANK[finding.severity] >= threshold
        for finding in result.findings
    ):
        return 2
    return 0
