---
layout: post
title:  "A Semgrep Rule Pack for Header-Trust Auth Bypass Patterns"
date:   2026-05-05 14:00:00 -0700
categories: tooling
tags: [semgrep, static-analysis, appsec, auth-bypass, cve-2025-29927]
---

## TL;DR

[`auth-header-trust-rules`](https://github.com/bk-security/auth-header-trust-rules)
is a small Semgrep pack I wrote to catch the vulnerability class behind
CVE-2025-29927: code that makes an authentication, authorization, or trust
decision based on an HTTP request header an attacker controls. Six rules
across JavaScript, TypeScript, and Python, covering three sub-classes of the
bug (auth-bypass header flags, identity-carrying headers, and forwarded-IP
headers used for security decisions). The pack is intended as a code-review
aid, not a fully-tuned CI gate.

## The Problem

[CVE-2025-29927](/writeup/2026/04/28/nextjs-cve-2025-29927.html) was the
canonical 2025 example of this bug class: Next.js trusted the
`x-middleware-subrequest` request header to decide whether middleware ran,
and any inbound request that supplied a crafted value could skip middleware
entirely. The same shape recurs across the stack, and most concrete instances
look benign in isolation. Three patterns in particular keep showing up.

The first is the **auth-bypass flag**: a request handler reads a header value
and uses it to short-circuit an authentication check. Internal-protocol
headers like `x-middleware-subrequest`, `x-internal`, or `x-skip-auth` are
intended for framework use but appear in inbound requests because the
framework does not strip them at the trust boundary.

The second is the **identity-carrying header**: a request handler reads
`X-Forwarded-User`, `X-Authenticated-User`, `X-Remote-User`, or similar, and
treats the value as the authenticated user identity. The pattern is common
behind a reverse proxy that performs authentication at the edge and is
supposed to strip incoming versions of these headers on every request. If the
proxy can be bypassed, or the application can be reached directly, the
attacker controls the identity.

The third is the **forwarded-IP header used for security**: code reads
`X-Forwarded-For` or `X-Real-IP` to make an allowlisting, rate-limiting, or
geo-blocking decision. These headers are trustworthy only when a known
reverse proxy sets them at the boundary and the application strips any
pre-existing values. The fallback case (the application sees a forwarded
header it did not expect) is bypassable by anyone who can connect to the
service.

All three patterns share one shape: a security-relevant decision made from a
request-scoped value the attacker can supply.

## The Design

Six rules, three subjects per language. The full pack:

| Rule | Language | Severity | Catches |
|------|----------|----------|---------|
| `nodejs-header-flag-auth-bypass` | JS / TS | Warning | Reads of internal-protocol-style header names |
| `nodejs-header-as-identity` | JS / TS | Warning | Reads of identity-carrying headers |
| `nodejs-forwarded-for-trust` | JS / TS | Info | Reads of source-IP headers |
| `python-header-flag-auth-bypass` | Python | Warning | Same, Python-flavored |
| `python-header-as-identity` | Python | Warning | Same, Python-flavored |
| `python-forwarded-for-trust` | Python | Info | Same, Python-flavored |

The rules are intentionally lexical. Each one matches a header read where the
header name belongs to a curated list of known-dangerous names, and the
object being read is constrained to look like an inbound HTTP request. A
representative rule (with comments) looks like this:

```yaml
rules:
  - id: nodejs-header-flag-auth-bypass
    languages: [javascript, typescript]
    severity: WARNING
    patterns:
      # The reads we want to catch: bracket access, .get(), or Express's .get().
      - pattern-either:
          - pattern: $REQ.headers[$NAME]
          - pattern: $REQ.headers.get($NAME)
          - pattern: $REQ.headers?.get($NAME)
          - pattern: $REQ?.headers.get($NAME)
          - pattern: $REQ.get($NAME)
      # The header name must look like an internal-protocol or bypass header.
      - metavariable-regex:
          metavariable: $NAME
          regex: '(?i)["''`](x-(internal|bypass|skip|admin-override|impersonate|middleware-subrequest|trust(ed)?(-source)?|debug-auth|test-auth|dev-auth|skip-auth|bypass-auth|forwarded-user|authenticated-user|remote-user|user-id|user-email|username))["''`]'
      # The receiver must look like an inbound request (not, say, an Axios
      # client whose `defaults.headers` happens to share the shape).
      - metavariable-regex:
          metavariable: $REQ
          regex: '^(.*\.)?(req|request|ctx|httpReq|httpRequest|event)$'
      # Reads only, not writes. `req.headers["x-foo"] = value` is the wrong direction.
      - pattern-not: $REQ.headers[$NAME] = $X
      - pattern-not: $REQ.headers.set($NAME, $X)
      - pattern-not: $REQ.set($NAME, $X)
```

Two design choices are worth pulling out.

The `$REQ`-constrained regex prevents the most common false positive class.
An early version of the rule matched any object with a `.headers` property,
which fires on outbound HTTP client configurations like `axios.defaults` or
on response objects. Pinning `$REQ` to identifiers that look like inbound
request variables (`req`, `request`, `ctx`, anything ending in `.req` or
`.request`) eliminates that class. It does mean codebases with unconventional
naming will miss findings, which is a recall sacrifice worth making.

The `pattern-not` clauses for assignment forms exclude `req.headers[name] =
value`, which Semgrep would otherwise match against the same pattern as a
read. Writes are not the bug; reads are.

## Usage

Install Semgrep:

```bash
pip install semgrep
```

Run the pack against a target codebase:

```bash
semgrep --config path/to/auth-header-trust-rules/rules path/to/target
```

Or run a single rule:

```bash
semgrep --config path/to/auth-header-trust-rules/rules/nodejs/header-flag-auth-bypass.yaml path/to/target
```

Validate the rules against the bundled fixtures:

```bash
cd path/to/auth-header-trust-rules
semgrep --test --config rules/ tests/
```

Expected output:

```
6/6: ✓ All tests passed
```

For CI use, point Semgrep at the rules and let it exit non-zero on findings:

```bash
semgrep --config path/to/auth-header-trust-rules/rules --error
```

That said, the rules favor recall over precision. The first time you run
them against a real codebase you will see findings that are legitimate
behavior (telemetry use of `X-Forwarded-For`, internal proxies that do strip
inbound headers correctly, code paths gated by a build flag). Triaging those
out is part of the work. Use the pack as a code-review aid first; only graduate
to CI gating after the false-positive rate on your codebase is known.

## Limitations

The rules will not catch:

- **Helper-hidden reads.** A function named `getInternalFlag(req)` that
  internally reads `x-some-novel-header` will pass the rules. The call site
  has no header name for the regex to match against. Codebases that wrap
  header access tend to do it consistently, so the right extension here is a
  codebase-specific rule that names the helper.
- **Novel header names.** The curated list covers the patterns commonly used
  in practice. A header named `x-something-custom-to-this-app` is the same
  vulnerability class but invisible to the rules until someone adds the name
  to the regex.
- **Cookies, query parameters, and body fields used the same way.** Same
  vulnerability class, different rule pack. A future addition.
- **Absence-based bypasses.** Some applications skip authentication when a
  header is *not* present (a misconfigured allowlist pattern). The current
  rules are read-and-use, not absence-based.

Limitations are not flaws as long as you know what the rules cover. The
target audience for the pack is a security reviewer using it during a code
review pass, not an autonomous gate. Findings are inputs to a triage step,
not conclusions.

## References

- The rule pack itself: [github.com/bk-security/auth-header-trust-rules](https://github.com/bk-security/auth-header-trust-rules)
- The CVE that motivated it: [CVE-2025-29927 writeup](/writeup/2026/04/28/nextjs-cve-2025-29927.html)
- Semgrep documentation on [rule writing](https://semgrep.dev/docs/writing-rules/overview)
- Semgrep documentation on [metavariable-regex](https://semgrep.dev/docs/writing-rules/rule-syntax#metavariable-regex)
- [GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw): the Next.js advisory for the canonical instance of this bug class
