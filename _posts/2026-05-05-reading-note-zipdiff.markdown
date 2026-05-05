---
layout: post
title:  "Reading Note: My ZIP Isn't Your ZIP (USENIX Security 2025)"
date:   2026-05-05 09:00:00 -0700
categories: reading-note
tags: [parsing-differentials, fuzzing, file-formats, usenix-security-2025]
---

## What It Is

"My ZIP Isn't Your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers." Yufan You, Jianjun Chen, Qi Wang, and Haixin Duan of Tsinghua University and Zhongguancun Laboratory. USENIX Security 2025. The paper introduces ZipDiff, a differential fuzzer for ZIP parsers, available at [github.com/ouuan/ZipDiff](https://github.com/ouuan/ZipDiff).

## The Claim

The ZIP format is old, the specification has accumulated ambiguities over decades, and every language ecosystem ships at least one parser. The authors built a differential fuzzer that compares parser behavior across implementations, ran it against 50 ZIP parsers spanning 19 programming languages, and identified 14 distinct parsing-ambiguity types organized into three categories: redundant metadata (fields stored twice in both the central directory and the local file headers, where the two copies can disagree), file path processing (filenames that two parsers normalize or split differently), and ZIP structure positioning (where in the file each parser starts looking for the canonical structure). Ten of the fourteen ambiguity types had not been previously documented. Each ambiguity is a place where two parsers given the same input produce different conceptual files, which is the precondition for the class of attack called parser differentials.

The paper opens by anchoring the work in the Android master key vulnerability from 2013, where a mismatch between the ZIP component that verified APK signatures and the component that decompressed contents allowed malicious code to run in privileged applications without breaking signatures. The authors take that one-off finding and turn it into a systematic taxonomy.

## What They Demonstrate

Five concrete attack scenarios, each grounded in a specific ambiguity from the taxonomy:

1. **Secure email gateway bypass.** A ZIP attached to an email is scanned as one set of files and extracted by the recipient as a different set. Reported to and rewarded by Gmail (rated medium severity, $1,337 bounty), Coremail, and Zoho.
2. **Office document content spoofing.** Office documents are ZIP archives. A document that displays one body when opened in one suite and a different body in another is, by definition, two different documents sharing one signature.
3. **LibreOffice signature forgery.** The verifier and the renderer disagreed about which `content.xml` is the canonical one. CVE assigned.
4. **Spring Boot nested JAR signature forgery.** Spring Boot's `NestedJarFile` class uses a custom ZIP parser that diverges from the JDK's. A signed JAR can be tampered with such that the JDK verifier still passes, but Spring Boot loads different code at runtime. CVE assigned.
5. **VS Code extension ID impersonation.** An extension package can be constructed so that the marketplace server accepts it under one identity while VS Code installs it under another.

Three CVEs total, assigned against Go, LibreOffice, and Spring Boot. The authors also propose seven mitigation strategies covering parser hardening, format-level changes, and downstream consumer practices.

## Why It Matters

Parser differentials are a recurring shape in security incidents that often gets discussed only in the specific instance. HTTP request smuggling is a parser differential between a front-end proxy and a back-end origin. Magic-byte versus extension confusion is a parser differential between an antivirus engine and the OS loader. The Application Policy versus EKU confusion in AD CS that I wrote about in the EKUwu post is a parser differential between two metadata extensions inside the same file format. The work named here adds a fourteen-way taxonomy for ZIP specifically, and a working tool to find the next instance.

ZIP is a particularly rich substrate for this class of bug because the format has a central directory at the end of the file, local file headers at the start, and the two are allowed to disagree on file names, compression methods, and contents. Different parsers prefer different sources of truth. An attacker who can predict which source each consumer prefers can construct a single archive that contains, conceptually, two different sets of files: one for the antivirus scanner that reads the central directory, one for the unzipper that reads the local headers, one for the signature verifier that reads everything but only checks one section.

The paper demonstrates these are not theoretical; the researchers drove their differentials against real-world tooling and found cases where files passed checks and emerged differently after extraction.

## Notes Worth Keeping

**Differentials scale with format complexity.** ZIP allows multiple places to put the same information. PDF has more. STIX, MIME, and Office Open XML all share the property. Any format whose specification leaves room for redundancy is a differential candidate, and the older the format, the more opportunities for divergent interpretations to have crystallized in independent implementations.

**Nineteen languages each shipping a parser is a guarantee, not a risk.** Independent reimplementations of a complex format will diverge. The lesson is operational: consumers downstream of any such format should treat parser output as untrusted until cross-checked, and pipelines that pass an archive through more than one parser (scan, then verify, then extract) should assume the parsers disagree somewhere.

**The class of attack generalizes.** When two systems agree on the wire format but disagree on the meaning, security checks based on one interpretation are bypassable by an attacker who controls the other. For an offensive engagement, the actionable rule is: when reviewing a multi-stage pipeline that touches a complex format, identify which parser is consulted at each stage, then construct an input whose meaning depends on which stage is asking. Treat parsing differentials as a primitive on the same shelf as type confusion, time-of-check-to-time-of-use, and double fetch. They are all variants of "the system used a value at moment A and a different value at moment B."

**The artifact is the interesting part.** ZipDiff is a tool you can run. The interesting follow-on work, for someone with assessment hours to spend, is to point it at the specific archive-handling pipelines in a real environment (security gateways, CI artifact storage, mobile app stores, OS update channels) and see what falls out.

## References

- [USENIX Security 2025 paper page](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Paper PDF](https://www.usenix.org/system/files/usenixsecurity25-you.pdf)
- [ZipDiff source code](https://github.com/ouuan/ZipDiff)
- [USENIX Security 2025 artifact appendix](https://secartifacts.github.io/usenixsec2025/appendix-files/sec25cycle2ae-final28.pdf)
