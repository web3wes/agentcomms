# Security policy

## Status and supported version

Protocol v2 and its implementation are new and have not been independently
audited. The latest PyPI release is the only supported package version.
Protocol v1 is retained for compatibility and must not be used to protect
serious secrets.

The documented limitations in `README.md`, `PROTOCOL_V2.md`, and `TRUST.md`
are not vulnerability claims; they are part of the stated threat model.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting form:

<https://github.com/web3wes/agentcomms/security/advisories/new>

Include the affected version or commit, a minimal reproduction, expected and
observed behavior, and potential impact. Do not include live private keys,
plaintext messages, or third-party credentials. If private reporting is not
available, open a public issue containing no exploit details and ask the
maintainer to establish a private channel.

No bounty or payment is currently offered. Reports will be acknowledged and
assessed without requiring the reporter to prove identity beyond the technical
evidence supplied.

## Supply-chain verification

Release artifacts are published from GitHub Actions to PyPI using OIDC Trusted
Publishing. PyPI exposes PEP 740/Sigstore provenance for each distribution.
Exact artifact hashes, provenance URLs, runtime permissions, and the current
SBOM are linked from:

<https://web3wes.pythonanywhere.com/.well-known/agentcomms-trust.json>
