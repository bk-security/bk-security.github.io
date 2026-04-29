---
layout: post
title:  "TITLE: short, descriptive, no clickbait"
date:   YYYY-MM-DD HH:MM:SS -0700
categories: writeup
tags: [target-tech, vuln-class]
---

## TL;DR

One paragraph. What's the bug, what does it get an attacker, why should the reader care. If they only read this section, what do they walk away with.

## Background

Two or three sentences on the target, the technology stack, and why this surface matters. Skip the OWASP 101.

## Lab Setup

Exact versions. Exact commands to spin it up. A reader should be able to copy-paste and reproduce.

```bash
# example
docker run -d -p 8080:80 vendor/app:1.2.3
```

## Discovery

How I noticed something was off. The dead ends count: list the things I tried first that didn't work, because that's where most of the learning is. Real timeline, not a sanitized one.

## Exploitation

The actual attack, in working order. Show the request or payload verbatim:

```http
POST /api/v1/example HTTP/1.1
Host: target.local
Content-Type: application/json

{"id": "../../etc/passwd"}
```

Then what the server returns and why that matters.

## Impact

Concrete. What can an attacker do, against what data, under what preconditions. Don't oversell, don't undersell. CVSS vector if relevant, with a note on which metric is the load-bearing one.

## Remediation

Specific. The fix, not "implement defense in depth." Point to the line, the config knob, the framework primitive that makes this go away. Mention what doesn't fix it (WAF rules, blocklists, etc).

## Disclosure Timeline

If applicable.

```
2026-MM-DD  Reported to vendor
2026-MM-DD  Vendor acknowledged
2026-MM-DD  Patch released as version X.Y.Z (CVE-YYYY-NNNNN)
2026-MM-DD  Public writeup
```

## References

* CVE record, NVD entry, vendor advisory
* Related prior research
* Specs, RFCs, or framework docs that explain the underlying mechanism

---

**Self-check before publishing**

* [ ] No client names, no internal hostnames, no real customer data anywhere in screenshots or payloads
* [ ] Lab setup is reproducible from a fresh machine
* [ ] CVE / advisory / disclosure status is accurate
* [ ] No em-dashes acting as soft commas; vary sentence length; first person; cut "delve / leverage / robust / comprehensive / ensure / foster / harness / underscore"
