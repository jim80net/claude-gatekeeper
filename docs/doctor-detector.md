# Scheduled Doctor detector

`doctor --json --check-latest` inventories live hook surfaces and independently
checks the outcome invariant:

```text
enforcing binary-reported version == latest published release
```

The enforcing version comes only from executing each discovered binary with
`--version`. If execution fails, the observation is `unknown`; directory names,
plugin manifests, and cached updater state are never version fallbacks. If the
release endpoint is unreachable, the invariant is also `unknown`. A mismatch is
`fail` and names both versions. For Claude plugin surfaces, a version-shaped
cache directory that disagrees with executable output is reported as a failure.

The JSON command exits non-zero for inventory drift, `fail`, or `unknown`.
Consumers must alert on every non-zero result and preserve stdout as the
machine-readable observation; stderr carries invocation errors.

The user-level systemd templates in `deploy/systemd/` run hourly with a small
random delay and are independent of release or updater events. Installing and
enabling them is a separate deployment action; this repository does not do so
automatically. Before enabling, verify that the service's binary path is the
fleet's enforcing binary and adjust `--min-surfaces` to the intended surface
count.
