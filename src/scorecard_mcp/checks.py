"""Static catalogue of Scorecard checks: risk level and a short remediation note.

Risk levels follow the Scorecard documentation (docs/checks.md). Remediation text is a brief
summary written for this project; the per-check documentation link is returned with every result.
"""

from __future__ import annotations

RISK_WEIGHT = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.5}

CHECKS: dict[str, dict[str, str]] = {
    "Binary-Artifacts": {
        "risk": "High",
        "what": "Generated executables (binaries) committed to the repository.",
        "fix": "Remove checked-in binaries and build them in CI instead; keep only tiny, reviewed test fixtures.",
    },
    "Branch-Protection": {
        "risk": "High",
        "what": "Branch protection rules on the default and release branches.",
        "fix": "Require pull requests, at least one approving review, passing status checks, and block force pushes and deletions; apply the rules to administrators too.",
    },
    "CI-Tests": {
        "risk": "Low",
        "what": "Whether merged pull requests run CI tests.",
        "fix": "Run tests on every pull request and make that check required before merging.",
    },
    "CII-Best-Practices": {
        "risk": "Low",
        "what": "OpenSSF Best Practices badge.",
        "fix": "Register the project at bestpractices.dev and work through the passing-level criteria.",
    },
    "Code-Review": {
        "risk": "High",
        "what": "Share of recent changes that were reviewed by someone other than the author.",
        "fix": "Require reviews before merge (branch protection or rulesets) and avoid merging your own unreviewed changes.",
    },
    "Contributors": {
        "risk": "Low",
        "what": "Whether contributors come from more than one organisation.",
        "fix": "Mostly informational; it improves only as more organisations contribute.",
    },
    "Dangerous-Workflow": {
        "risk": "Critical",
        "what": "GitHub Actions patterns that allow script injection or untrusted code to run with secrets.",
        "fix": "Do not check out untrusted pull request code in pull_request_target workflows, and pass untrusted values (titles, branch names) through environment variables instead of inline ${{ }} expressions.",
    },
    "Dependency-Update-Tool": {
        "risk": "High",
        "what": "Use of an automated dependency update tool.",
        "fix": "Enable Dependabot or Renovate for every ecosystem in the repository, including GitHub Actions.",
    },
    "Fuzzing": {
        "risk": "Medium",
        "what": "Whether the project is fuzzed.",
        "fix": "Add language-native fuzz tests, or onboard to OSS-Fuzz or ClusterFuzzLite.",
    },
    "License": {
        "risk": "Low",
        "what": "Presence of a recognised licence file.",
        "fix": "Add a LICENSE file with an OSI- or FSF-recognised licence text.",
    },
    "Maintained": {
        "risk": "High",
        "what": "Recent commit and issue activity (last 90 days).",
        "fix": "Mostly reflects activity; archived or very new repositories also score low. Triage issues and ship regular updates.",
    },
    "Packaging": {
        "risk": "Medium",
        "what": "Whether releases are published through a recognised packaging workflow.",
        "fix": "Publish to the package registry from a CI workflow (for example trusted publishing) rather than by hand.",
    },
    "Pinned-Dependencies": {
        "risk": "Medium",
        "what": "Build and CI dependencies pinned by hash (actions, container images, install commands).",
        "fix": "Pin GitHub Actions to full commit SHAs, container images to digests, and install with lockfiles and hashes.",
    },
    "SAST": {
        "risk": "Medium",
        "what": "Static analysis run on pull requests or commits.",
        "fix": "Enable CodeQL or another SAST tool and run it on every pull request.",
    },
    "SBOM": {
        "risk": "Medium",
        "what": "Whether releases ship a software bill of materials.",
        "fix": "Generate an SBOM (SPDX or CycloneDX) in the release workflow and attach it to each release.",
    },
    "Security-Policy": {
        "risk": "Medium",
        "what": "A published security policy (SECURITY.md).",
        "fix": "Add a SECURITY.md that says how to report a vulnerability and what response to expect.",
    },
    "Signed-Releases": {
        "risk": "High",
        "what": "Cryptographic signatures or provenance on release artifacts.",
        "fix": "Sign release artifacts (Sigstore/cosign or GPG) and publish SLSA provenance from the release workflow.",
    },
    "Token-Permissions": {
        "risk": "High",
        "what": "Least-privilege GITHUB_TOKEN permissions in workflows.",
        "fix": "Set 'permissions: read-all' (or 'contents: read') at the top of each workflow and grant write scopes only on the jobs that need them.",
    },
    "Vulnerabilities": {
        "risk": "High",
        "what": "Known, unfixed vulnerabilities in the project's dependencies (matched against OSV).",
        "fix": "Upgrade or replace the affected dependencies; the warning lines name the advisory ids.",
    },
    "Webhooks": {
        "risk": "Critical",
        "what": "Repository webhooks that do not use a secret.",
        "fix": "Configure a secret on every webhook and verify the signature on the receiving side.",
    },
}


def info(name: str) -> dict[str, str]:
    """Catalogue entry for a check, matched case-insensitively; unknown checks default to Medium risk."""
    for key, val in CHECKS.items():
        if key.lower() == name.lower():
            return {"name": key, **val}
    return {"name": name, "risk": "Medium", "what": "", "fix": ""}


def canonical(name: str) -> str | None:
    for key in CHECKS:
        if key.lower() == name.strip().lower().replace("_", "-").replace(" ", "-"):
            return key
    return None
