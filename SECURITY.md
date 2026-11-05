# Security policy

## Supported versions

Security fixes go into the latest release of ctfkit by compliance.tf, including a prerelease
when that is the latest. Older releases do not get fixes; upgrade to the latest
release to pick one up.

## Reporting a vulnerability

Report a vulnerability privately through GitHub: open
<https://github.com/compliancetf/ctfkit/security/advisories/new>, or use "Report a
vulnerability" on the repository's Security tab. Do not open a public issue, pull request or
discussion for it.

Include what you can of:

- the output of `ctfkit version`;
- the command, stage and inputs that trigger the problem, reduced to a small example with no
  secrets, account ids or resource names from your estate;
- what an attacker gains, and what they need to control to get it.

We acknowledge a report on GitHub, keep you updated in the advisory, and credit you in it
unless you ask us not to. We publish the advisory when a fixed release is out.

## Scope

ctfkit runs on your machines and in your CI, on configuration, plans and module manifests you
give it. In scope: anything in this repository, the release archives and packages, and the
container image built from it. A finding ctfkit misses or reports wrongly is a bug: open a
regular issue unless the miss can be triggered on purpose to hide a change.
