# Scheduled Doctor detector

`doctor --json --check-latest` inventories live hook surfaces and independently
checks the outcome invariant:

```text
enforcing binary-reported version == latest published release
```

The enforcing version comes only from executing each discovered binary with
`--version`; directory names, plugin manifests, and cached updater state are
never version fallbacks. The invariant's status is a machine-readable contract:

- `current` — every executable-reported version matches the published release.
- `stale` — an enforcing or plugin-path version differs; the reason names the
  observed and published versions.
- `misconfigured` — a pre-probe deployment requirement is absent or invalid.
  The release source is not contacted.
- `unreachable` — preflight passed, the release probe ran, and it failed.
- `unknown` — residual evidence cannot be classified, such as an executable
  version probe that produced no version.

Deployments that require environment-specific proxy, token, or trust settings
must declare each prerequisite with repeatable `--latest-require-env NAME` unit
arguments. A missing or empty declared variable reports `misconfigured` before
HTTP. The default public endpoint requires no deployment-specific variable.
For Claude plugin surfaces, a version-shaped cache directory that disagrees
with executable output reports `stale`.

The JSON command exits non-zero for inventory drift or any invariant status
other than `current`.
Consumers must alert on every non-zero result and preserve stdout as the
machine-readable observation; stderr carries invocation errors.

The user-level systemd templates in `deploy/systemd/` run hourly with a small
random delay and are independent of release or updater events. Installing and
enabling them is a separate deployment action; this repository does not do so
automatically. Before enabling, verify that the service's binary path is the
fleet's enforcing binary and adjust `--min-surfaces` to the intended surface
count. If that unit depends on environment-only network capability, add the
matching `--latest-require-env` declarations to the installed unit and confirm
the variables are actually present in the unit environment.
