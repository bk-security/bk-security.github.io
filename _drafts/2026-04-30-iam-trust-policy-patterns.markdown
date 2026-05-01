---
layout: post
title:  "IAM Trust Policy Abuse: Patterns Scanners Miss"
date:   2026-04-30 09:00:00 -0700
categories: writeup
tags: [aws, iam, cloud-security, trust-policy, confused-deputy, github-actions-oidc]
---

## TL;DR

A trust policy is the resource-based access-control document attached to an IAM role; it is the gate that decides who can assume the role. Automated scanners catch the obvious mistakes (wildcards in `Principal`, missing condition blocks), but the patterns that show up in real engagements tend to live in subtler territory. This post walks through five of them: ExternalId values that appear in the policy but are not actually validated by the vendor, GitHub Actions OIDC `sub` claims that scope to org-wide wildcards, AWS service trust missing `aws:SourceArn` or `aws:SourceAccount`, account-root principals with no additional conditions, and stale trust relationships left behind after services are decommissioned. Each one looks correct at first glance and fails when an unstated assumption is violated.

## Credit and Disclosure

This post draws on public research from Praetorian's vendor survey of confused deputy implementations, Datadog Security Labs and Tinder's writeups on GitHub Actions OIDC misconfigurations, Rhino Security Labs' AWS IAM privilege escalation taxonomy, and Unit 42's threat research on default IAM roles. None of the discovery is mine; what follows is my synthesis of their work plus patterns I have seen recur across assessments.

Disclosure: I worked at Praetorian until March 2026. I am citing Praetorian's published research below the same way I would any other public source, but the prior employment is worth naming up front.

## A Brief Primer on Trust Policies

For the rest of the post to make sense, a moment on what a trust policy actually is.

Every IAM role has two policy documents attached to it: a permissions policy (what the role can do) and a trust policy (who can become the role). The trust policy, also called the assume-role policy document, is a resource-based policy on the role itself. When some principal calls `sts:AssumeRole` against a role's ARN, AWS evaluates the trust policy to decide whether to issue temporary credentials.

A trust policy declares a principal in one of four shapes: an AWS account, user, or role ARN; a federated identity provider (SAML or OIDC); an AWS service principal (`lambda.amazonaws.com`, `ec2.amazonaws.com`); or a canonical user ID. Each shape has its own failure modes.

Conditions on the trust policy work the same way they do anywhere else in IAM. The interesting part is that conditions are often the only thing standing between a permissive principal and an attacker. Get the principal scoping right and conditions are belt-and-suspenders. Get the principal scoping loose and conditions become the only protection.

With that out of the way, the patterns.

## Pattern 1: ExternalId Present in the Policy but Not Validated by the Vendor

Imagine a SaaS vendor that integrates with your AWS account to read CloudWatch metrics. The vendor instructs you to create an IAM role with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::987654321098:root" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "abc-1234-customer-id" }
    }
  }]
}
```

The vendor's account ID is `987654321098`. The `ExternalId` is supposed to be a unique value the vendor associates with you, the customer. When the vendor's backend calls `sts:AssumeRole` against your role, it is meant to pass that exact ExternalId.

Why does this matter? Because the vendor has many customers, and each customer trusts the vendor's account `987654321098`. Without the ExternalId check, a malicious customer of the vendor could trick the vendor into calling `sts:AssumeRole` against *your* role's ARN. That is the AWS confused deputy problem: the vendor has the privilege to assume into many roles, but does not always know which of its customers' roles is the legitimate target of a given action.

The trust policy above looks correct. The mistake lives on the vendor's side, not yours. If the vendor's backend allows a customer to specify an arbitrary ExternalId in an API request, an attacker can configure the vendor's integration to point at a victim customer's role ARN, supply the victim's ExternalId (which is sometimes guessable, occasionally just the victim's account ID), and have the vendor's role assume into the victim's account on the attacker's behalf.

Praetorian (where I worked until March 2026) ran a survey of 90 SaaS vendors that perform cross-account integrations. Of those, 37% had not implemented ExternalId correctly against confused-deputy attacks. A further 15% had UI flows that handled ExternalId correctly but backend APIs that accepted tampered values via PUT or POST, putting the combined vulnerable share at roughly half. The most common failure mode in the second bucket was a UI that presented the ExternalId as immutable while the underlying API accepted any value the request body contained.

This vulnerability class is called the vendor-side confused deputy. From the customer's side, the trust policy looks like best-practice; from the vendor's side, the API does not enforce what the policy assumes it enforces.

What to look for: when assessing a vendor integration, intercept the integration setup or update calls. Try modifying the ExternalId in the request body. If the modification persists and the vendor still successfully assumes into your account, the vendor has the bug. If you are the vendor, validate the ExternalId server-side at every entry point that creates or modifies a customer integration.

## Pattern 2: GitHub Actions OIDC `sub` Claims with Subtle Wildcards

GitHub Actions can authenticate to AWS using OIDC, eliminating the need to store long-lived AWS credentials in repository secrets. The trust relationship is set up by adding GitHub's OIDC provider to the AWS account and configuring an IAM role with a trust policy that accepts JWTs from `token.actions.githubusercontent.com`.

The `sub` (subject) claim in the JWT identifies what is running. Its format is structured: `repo:my-org/my-repo:ref:refs/heads/main` for a workflow on the `main` branch, `repo:my-org/my-repo:environment:production` for a workflow that requested the `production` environment, `repo:my-org/my-repo:pull_request` for PR-triggered workflows, and so on.

The trust policy uses a condition to constrain which `sub` values can assume the role. A correct policy looks like this:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:environment:production"
    }
  }
}
```

The egregious misconfiguration is `"sub": "*"` or no condition at all, which allows any GitHub Actions workflow on the public internet to assume the role. AWS started blocking the creation of new roles with this pattern in June 2025. Existing roles created before that date persist.

The subtler and more common misconfiguration is the org-wide wildcard:

```json
"StringLike": {
  "token.actions.githubusercontent.com:sub": "repo:my-org/*"
}
```

This looks like reasonable scoping. It is not. It allows any repository in `my-org` to assume the role, including a fork, a newly created internal repo with weaker review controls, a malicious commit pushed by a compromised developer to a low-traffic repo, or a Dependabot-style automation that runs unreviewed code. If `my-org` has more than a small number of repositories, the trust boundary is significantly wider than the role's intended scope.

This vulnerability class is called audience scope creep. The fix is to scope `sub` to specific repositories and ideally specific environments or refs:

```json
"StringEquals": {
  "token.actions.githubusercontent.com:sub": [
    "repo:my-org/deploy-prod:environment:production",
    "repo:my-org/deploy-staging:environment:staging"
  ]
}
```

What to look for: enumerate every IAM role in the account, parse the trust policies for the GitHub Actions OIDC provider ARN, and flag any role whose `sub` condition uses `StringLike` with a wildcard, or that has no `sub` condition at all. This is the kind of finding that justifies an immediate fix even on roles with apparently low blast radius, because GitHub Actions makes it easy for the blast radius to expand silently.

## Pattern 3: Service Trust Without `aws:SourceArn` or `aws:SourceAccount`

When an AWS service assumes a role on your behalf, the trust policy designates a service principal:

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "cloudformation.amazonaws.com" },
  "Action": "sts:AssumeRole"
}
```

This says "the CloudFormation service can assume this role." On the surface that sounds reasonable. The role is for CloudFormation, after all.

The problem is that "the CloudFormation service" is not a single thing scoped to your account. It is an AWS-wide service that runs CloudFormation on behalf of every AWS customer. Without additional scoping, any caller in any AWS account that can configure the service to act against your role becomes a confused-deputy primitive. The pattern shows up most often in services where the trust boundary is less obvious than CloudFormation: SNS topic publishers, Lambda function invokers, and various integration services where one AWS principal can configure another service to act on a third party's resource.

The fix is to scope service trust to specific source resources and source accounts:

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "cloudformation.amazonaws.com" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "111122223333"
    },
    "ArnEquals": {
      "aws:SourceArn": "arn:aws:cloudformation:us-east-1:111122223333:stack/MyStack/*"
    }
  }
}
```

The `aws:SourceAccount` condition pins the request to a specific AWS account. The `aws:SourceArn` condition pins it to a specific resource in that account.

This vulnerability class is the service confused deputy. The fix has been documented by AWS for years and is now the recommended pattern in their service-integration guides, but service trust policies created before the recommendation became standard often lack these conditions, and there is no automatic migration.

What to look for: any trust policy with a `Service` principal and no `aws:SourceAccount` or `aws:SourceArn` condition is worth investigating. The fix is straightforward; the discovery work is the bottleneck.

## Pattern 4: Account-Root Principals Without Additional Conditions

This trust policy fragment is extremely common:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
  "Action": "sts:AssumeRole"
}
```

It allows account `123456789012` to assume the role. What is less obvious is that "account `123456789012`" means any IAM principal in that account that has `sts:AssumeRole` permission on this role's ARN. It is not pinned to a specific user or role.

In a healthy state, account `123456789012` only grants `sts:AssumeRole` to a small number of carefully-managed identities. But accounts evolve. New users get created. New roles get added. Permissions drift. A trust policy that delegated to account `123456789012` two years ago, when the only principal in that account with `sts:AssumeRole` was a single deployment role, may today implicitly trust dozens of human users.

The fix is to scope down with conditions:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "ArnEquals": {
      "aws:PrincipalArn": "arn:aws:iam::123456789012:role/DeploymentRole"
    }
  }
}
```

Or to skip the root principal entirely and pin the trust to a specific role ARN:

```json
"Principal": { "AWS": "arn:aws:iam::123456789012:role/DeploymentRole" }
```

The second form fails closed if the trusted role ever gets deleted; the first form allows for some flexibility while still bounding the trust to a specific principal.

It is important to remember that account-root principals are not inherently wrong. They are appropriate when the trusting and trusted accounts are under the same operational control and the operator wants flexibility in which specific principal can assume. They become a problem when the trusting account does not have visibility into how `sts:AssumeRole` permission is granted in the trusted account.

## Pattern 5: Stale Trust from Decommissioned Services

Trust policies accumulate. Over the lifetime of an AWS account, vendors get integrated, services get deployed, partners get granted access. When those integrations end, the role permissions usually get cleaned up. The trust policy on the partner's side is reviewed. The role on the customer side is sometimes deleted. But the trust policies on roles that delegated to those services often linger, particularly when the role has other purposes besides the now-decommissioned integration.

A trust policy that delegates to AWS account `444455556666` may have made sense in 2022 when `444455556666` was a vendor your organization actively used. It may not make sense in 2026 when the contract has lapsed, the vendor has been acquired, or the AWS account ID has been released back into AWS's pool and reassigned to an unrelated entity.

This vulnerability class is trust accumulation. The fix is operational rather than technical: every trust policy should be reviewed periodically (annually at minimum), the trusted entity validated as still belonging to the expected party, and any unused trust removed.

What to look for: the audit pattern is to enumerate every trust principal across every role, then verify that each external account ID still corresponds to the entity you think it does, and that the integration is still active. AWS does not provide a built-in tool for this; it is a custom script worth writing once and running every quarter.

## A Code-Review Checklist

For every trust policy in your environment, the audit pass:

1) Is there any non-service principal? If so, is it pinned to a specific ARN, or to an account root with conditions?

2) For every federated OIDC principal, is the `sub` (or audience-equivalent) condition pinned to specific identifiers, with no `StringLike` wildcards?

3) For every account-level AWS principal, is there an `aws:PrincipalArn` or `aws:PrincipalTag` condition that scopes the trust further?

4) For every external AWS account, does the trust policy include a strong `sts:ExternalId` condition? If you are the trusting party, have you verified the vendor validates the ExternalId on their backend?

5) For every AWS service principal, is there an `aws:SourceArn` or `aws:SourceAccount` condition?

6) For every trust principal, was it created or last reviewed within the last twelve months, and is the trusted entity still active and still in use?

A trust policy that fails any of these is worth a deeper look.

## Why Scanners Miss These

IAM Access Analyzer is the AWS-native tool most teams reach for. It is good at flagging trust policies that grant access to external accounts in general, and it has improved at recognizing OIDC and SAML federation. It does not deeply parse condition logic. A trust policy with `repo:my-org/*` will surface as "external access from GitHub Actions" but Access Analyzer will not tell you the wildcard is the problem.

Cloudsplaining focuses on permissions policies, not trust policies. ScoutSuite, Prowler, and Steampipe each have partial coverage of trust-policy issues, but the depth varies and false positives are common enough that teams tune them down. None of them validate the vendor side of an ExternalId trust, because that data is not visible from the AWS account being scanned.

The shape of a useful custom audit is straightforward: pull every role's trust policy, parse it as JSON, walk the statement objects, apply the six checks above, output a CSV. Two hundred lines of Python. Worth writing once.

## The Lesson That Generalizes

Trust policies are configured once and forgotten. All five patterns above share a common shape: the policy looks fine, but has a hidden assumption baked in. The vendor will validate ExternalId. The org will not have any malicious internal repos. The service will only be invoked by my own account. The trusted account will keep its permission grants tight. The trusted entity will remain the entity I trusted at setup.

Trust boundaries fail when assumptions fail. The actionable rule is to write the assumption down, then test it, then arrange for it to be tested again next quarter. Anything else is hope.

## Final Thoughts

If you have an AWS environment of any size, the quick win is to audit the trust policies on the top 10% of roles by privilege level this quarter. The investment is to bake the six-step checklist into CI for every new role. The long-term fix is to treat IAM Access Analyzer findings as a starting point, not a stopping point.

IAM trust is the surface where many of the worst cloud incidents start. The good news is that the patterns are knowable and the audits are tractable. The hard part is doing the work.

## References

- [Praetorian: AWS IAM Assume Role Vulnerabilities Found in Many Top Vendors](https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/)
- [Datadog Security Labs: No Keys Attached, Exploring GitHub-to-AWS Keyless Authentication Flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/)
- [Tinder Tech Blog: Identifying Vulnerabilities in GitHub Actions and AWS OIDC Configurations](https://medium.com/tinder/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations-8067c400d5b8)
- [Rhino Security Labs: AWS IAM Privilege Escalation Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Unit 42: Misconfigured IAM Roles Lead to Thousands of Compromised Cloud Workloads](https://unit42.paloaltonetworks.com/iam-roles-compromised-workloads/)
- [AWS docs: The Confused Deputy Problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [AWS docs: How to Use Trust Policies with IAM Roles](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)
