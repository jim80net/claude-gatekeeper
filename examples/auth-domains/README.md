# Authorization Domains D1/I1a fixtures

These files are synthetic. The object URI is a logical contract identifier, not
a credential path, and no file here contains or locates credential material.

```text
claude-gatekeeper auth-domains shadow \
  --policy examples/auth-domains/policy.json \
  --request examples/auth-domains/request-protected.json \
  --coverage examples/auth-domains/coverage.json
```

The protected example reports a simulated `deny_blocked`; the ordinary request
reports `permit_unblocked`. Both are inspection only: `enforcement` is always
false, and the command never emits a harness permission verdict.
