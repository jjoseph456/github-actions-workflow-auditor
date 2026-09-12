"""Audit GitHub Actions workflow YAML without executing workflow code."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
IMMUTABLE_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
UNTRUSTED_EXPRESSIONS = (
    "${{ github.event.",
    "${{ github.head_ref",
    "${{ inputs.",
)


class AuditError(ValueError):
    """Raised when a workflow cannot be read or parsed."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    source: str
    location: str


@dataclass(frozen=True)
class AuditResult:
    files_scanned: int
    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        return {
            severity: sum(
                finding.severity == severity for finding in self.findings
            )
            for severity in ("critical", "high", "medium", "low")
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "counts": self.counts(),
            "findings": [asdict(finding) for finding in self.findings],
        }


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _triggered(workflow: dict[str, Any], event: str) -> bool:
    triggers = workflow.get("on")
    if isinstance(triggers, str):
        return triggers == event
    if isinstance(triggers, list):
        return event in triggers
    if isinstance(triggers, dict):
        return event in triggers
    return False


def _permissions(workflow: dict[str, Any], job: dict[str, Any]) -> Any:
    return job.get("permissions", workflow.get("permissions"))


def _has_write_permission(value: Any) -> bool:
    if value == "write-all":
        return True
    return isinstance(value, dict) and any(
        permission == "write" for permission in value.values()
    )


def _remote_action_is_mutable(uses: str) -> bool:
    if uses.startswith(("./", "docker://")):
        return False
    if "@" not in uses:
        return True
    return not bool(IMMUTABLE_SHA.fullmatch(uses.rsplit("@", 1)[1]))


def _add(
    findings: list[Finding],
    condition: bool,
    rule_id: str,
    severity: str,
    message: str,
    source: Path,
    location: str,
) -> None:
    if condition:
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                source=str(source),
                location=location,
            )
        )


def audit_workflow(workflow: dict[str, Any], source: Path) -> list[Finding]:
    findings: list[Finding] = []
    permissions = workflow.get("permissions")

    _add(
        findings,
        "permissions" not in workflow,
        "GHA001",
        "high",
        "Define explicit top-level permissions instead of relying on defaults.",
        source,
        "workflow",
    )
    _add(
        findings,
        permissions == "write-all",
        "GHA002",
        "critical",
        "Replace write-all with the minimum permissions required.",
        source,
        "permissions",
    )
    _add(
        findings,
        "concurrency" not in workflow,
        "GHA003",
        "low",
        "Add concurrency controls to cancel or serialize redundant runs.",
        source,
        "workflow",
    )

    pull_request_target = _triggered(workflow, "pull_request_target")
    jobs = _mapping(workflow.get("jobs"))
    for job_name, raw_job in jobs.items():
        job = _mapping(raw_job)
        location = f"jobs.{job_name}"

        if "uses" in job:
            _add(
                findings,
                job.get("secrets") == "inherit",
                "GHA009",
                "medium",
                "Avoid inheriting every secret into a reusable workflow.",
                source,
                location,
            )
            continue

        _add(
            findings,
            "timeout-minutes" not in job,
            "GHA004",
            "medium",
            "Set timeout-minutes so stalled jobs cannot consume a runner indefinitely.",
            source,
            location,
        )

        job_permissions = _permissions(workflow, job)
        id_token_write = (
            isinstance(job_permissions, dict)
            and job_permissions.get("id-token") == "write"
        )
        _add(
            findings,
            id_token_write and "environment" not in job,
            "GHA008",
            "medium",
            "Pair OIDC token access with a protected deployment environment.",
            source,
            location,
        )

        for index, raw_step in enumerate(_sequence(job.get("steps")), 1):
            step = _mapping(raw_step)
            step_location = f"{location}.steps[{index}]"
            uses = step.get("uses")
            if isinstance(uses, str):
                _add(
                    findings,
                    _remote_action_is_mutable(uses),
                    "GHA005",
                    "medium",
                    f"Pin {uses.split('@', 1)[0]} to a full commit SHA.",
                    source,
                    step_location,
                )

            command = step.get("run")
            if isinstance(command, str):
                _add(
                    findings,
                    any(expression in command for expression in UNTRUSTED_EXPRESSIONS),
                    "GHA006",
                    "high",
                    "Do not interpolate event or workflow input data directly into shell code.",
                    source,
                    step_location,
                )

            if (
                pull_request_target
                and isinstance(uses, str)
                and uses.startswith("actions/checkout@")
            ):
                checkout_config = _mapping(step.get("with"))
                checkout_values = " ".join(
                    str(value) for value in checkout_config.values()
                )
                _add(
                    findings,
                    "github.event.pull_request.head" in checkout_values,
                    "GHA007",
                    "critical",
                    "Do not check out pull-request head code in pull_request_target.",
                    source,
                    step_location,
                )

        _add(
            findings,
            pull_request_target and _has_write_permission(job_permissions),
            "GHA010",
            "high",
            "Review write permissions on pull_request_target; untrusted pull requests can cross a privileged boundary.",
            source,
            location,
        )

    return findings


def audit_file(path: Path) -> list[Finding]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise AuditError(f"could not read {path}: {error}") from error

    try:
        workflow = yaml.load(raw, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise AuditError(f"invalid YAML in {path}: {error}") from error

    if not isinstance(workflow, dict):
        raise AuditError(f"{path} must contain a YAML mapping")
    if "jobs" not in workflow:
        raise AuditError(f"{path} does not contain a jobs mapping")

    return audit_workflow(workflow, path)


def discover_files(paths: Iterable[Path]) -> list[Path]:
    discovered: set[Path] = set()
    for path in paths:
        if path.is_file():
            discovered.add(path)
            continue
        if not path.exists():
            raise AuditError(f"path does not exist: {path}")

        workflow_directory = path / ".github" / "workflows"
        search_root = workflow_directory if workflow_directory.is_dir() else path
        discovered.update(search_root.rglob("*.yml"))
        discovered.update(search_root.rglob("*.yaml"))

    files = sorted(discovered)
    if not files:
        raise AuditError("no YAML workflow files found")
    return files


def audit_paths(paths: Iterable[Path]) -> AuditResult:
    files = discover_files(paths)
    findings: list[Finding] = []
    for path in files:
        findings.extend(audit_file(path))
    findings.sort(
        key=lambda finding: (
            -SEVERITY_RANK[finding.severity],
            finding.source,
            finding.location,
            finding.rule_id,
        )
    )
    return AuditResult(files_scanned=len(files), findings=tuple(findings))
