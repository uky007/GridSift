# Security policy

gridsift handles evidence. A bug that lets it write over a source file,
attach a stale digest to an export, or reach the network is a security
issue, not just a defect.

## Reporting

Please report vulnerabilities privately through GitHub's *Report a
vulnerability* form on this repository (Security → Advisories; the form
is available once the repository is public and private vulnerability
reporting is switched on in its settings) rather than in a public issue.
Include the version or commit, the platform, and the steps or files that
reproduce the problem. This is a small, volunteer-maintained project:
reports are acknowledged as soon as possible, and fixes are published as
a new release together with the advisory.

## In scope

- Any write to a file that gridsift did not create itself (the source, a
  lookup table, an MMDB, an existing unrelated file), including through
  temporary files or path tricks.
- An export that succeeds with a manifest that does not describe it: wrong
  source digest, missing or mis-recorded operations, a partial scan
  recorded as complete.
- Any network activity by `gridsift` or `gridsift-desktop`.
- Panics or unbounded memory on crafted input (malformed CSV, MMDB, lookup
  tables, manifests).
- Secrets in manifests or logs: an HMAC key, or anything beyond the
  documented key fingerprint.

## Out of scope

- Findings that require modifying the gridsift binary or its host.
- The confidentiality of a manifest that the analyst chose to share; the
  manifest is documented to contain paths and search terms.
