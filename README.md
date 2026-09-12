# GitHub Actions Workflow Auditor

[![CI](https://github.com/jjoseph456/github-actions-workflow-auditor/actions/workflows/test.yml/badge.svg)](https://github.com/jjoseph456/github-actions-workflow-auditor/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A static Python CLI that reviews GitHub Actions workflow YAML for high-impact
security and reliability risks. It does not execute workflow code or require
repository access beyond the files being scanned.

This is a personal, unofficial project based on public GitHub Actions security
guidance. All included workflows and reports are synthetic.

## Why This Project

Workflow failures and security exposures often come from a small set of
repeatable design problems: excessive permissions, mutable dependencies,
untrusted input reaching a shell, unsafe privileged-event checkouts, missing
timeouts, and weak deployment boundaries. `workflow-audit` turns those review
points into repeatable checks with automation-friendly output and exit codes.

## Checks

| Rule | Severity | Check |
| --- | --- | --- |
| `GHA001` | High | Missing explicit top-level permissions |
| `GHA002` | Critical | `permissions: write-all` |
| `GHA003` | Low | Missing workflow concurrency controls |
| `GHA004` | Medium | Missing job timeout |
| `GHA005` | Medium | Action not pinned to a full commit SHA |
| `GHA006` | High | Event or workflow input interpolated directly into shell code |
| `GHA007` | Critical | Pull-request head checkout under `pull_request_target` |
| `GHA008` | Medium | OIDC token permission without a deployment environment |
| `GHA009` | Medium | Reusable workflow inherits every secret |
| `GHA010` | High | Write permissions used with `pull_request_target` |

Findings are review signals, not proof of exploitability. Repository context
and intended behavior still matter.

## Install

```bash
git clone https://github.com/jjoseph456/github-actions-workflow-auditor.git
cd github-actions-workflow-auditor
python -m pip install .
```

## Usage

Audit workflows found under `.github/workflows`:

```bash
workflow-audit .
```

Audit one file and return status `2` for medium-or-higher findings:

```bash
workflow-audit .github/workflows/deploy.yml --fail-on medium
```

Generate machine-readable output:

```bash
workflow-audit . --format json
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed without findings at the configured failure threshold |
| `1` | Input, file, or YAML parsing error |
| `2` | At least one finding met the configured failure threshold |

## Example

```text
Scanned:  1 workflow file(s)
Findings: 2 critical, 2 high, 2 medium, 1 low

[CRITICAL] GHA002 examples/insecure.yml
  Location: permissions
  Replace write-all with the minimum permissions required.

[CRITICAL] GHA007 examples/insecure.yml
  Location: jobs.review.steps[1]
  Do not check out pull-request head code in pull_request_target.
```

See the [complete example report](examples/example-report.md), the
[insecure workflow](examples/insecure.yml), and its
[hardened counterpart](examples/secure.yml).

## Review Method

This tool supports a structured GitHub Actions workflow review:

1. Inventory workflow entry points, permissions, dependencies, and deployment
   boundaries.
2. Run repeatable static checks.
3. Manually validate context-sensitive findings.
4. Deliver a prioritized remediation report with hardened workflow examples.
5. Re-run the audit as a CI gate after remediation.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
workflow-audit examples/secure.yml
```

## Limitations

- The auditor does not expand reusable workflows or evaluate organization and
  enterprise policy.
- It does not prove that an expression is exploitable.
- It does not validate cloud-provider OIDC trust policies.
- It complements GitHub security controls and manual review; it does not
  replace them.
