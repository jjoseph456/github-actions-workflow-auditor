# Example Audit Report

Input: `examples/insecure.yml`

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

The complete CLI output also identifies direct event-data interpolation,
mutable action references, missing job timeouts, missing concurrency controls,
and privileged `pull_request_target` permissions.
