"""Response shaping for each tool. Pure async functions over a ScorecardClient."""

from __future__ import annotations

import asyncio
from typing import Any

from .checks import CHECKS, RISK_WEIGHT, canonical, info
from .client import ScorecardClient, ScorecardError

CONCURRENCY = 6
MAX_REPOS = 30


def rating(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 8:
        return "strong"
    if score >= 6:
        return "fair"
    if score >= 4:
        return "weak"
    return "poor"


def _scored(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Checks with a real score. Scorecard uses -1 for 'could not evaluate'."""
    return [c for c in raw.get("checks", []) if isinstance(c.get("score"), int | float) and c["score"] >= 0]


def _inconclusive(raw: dict[str, Any]) -> list[str]:
    return sorted(c["name"] for c in raw.get("checks", []) if not (isinstance(c.get("score"), int | float) and c["score"] >= 0))


def _priority(check: dict[str, Any]) -> float:
    return RISK_WEIGHT[info(check["name"])["risk"]] * (10 - check["score"])


def _lines(details: list[str] | None, limit: int, warn_only: bool = True) -> tuple[list[str], int]:
    """Trim detail lines: Warn lines first, each cut to 220 chars. Returns (lines, total_available)."""
    details = [d for d in (details or []) if isinstance(d, str)]
    warns = [d for d in details if d.startswith("Warn")]
    chosen = warns if (warn_only and warns) else details
    return [d[:220] for d in chosen[: max(limit, 0)]], len(chosen)


def _header(raw: dict[str, Any]) -> dict[str, Any]:
    repo = raw.get("repo") or {}
    sc = raw.get("scorecard") or {}
    return {
        "repo": repo.get("name"),
        "commit": repo.get("commit"),
        "scanned": (raw.get("date") or "")[:10],
        "scorecard_version": sc.get("version"),
        "score": raw.get("score"),
        "rating": rating(raw.get("score")),
    }


async def repo_score(c: ScorecardClient, repo: str, commit: str | None = None, all_checks: bool = False) -> dict[str, Any]:
    raw = await c.result(repo, commit)
    checks = sorted(_scored(raw), key=lambda ch: (-_priority(ch), ch["name"]))
    out = _header(raw)
    out["checks_scored"] = len(checks)
    picked = checks if all_checks else [ch for ch in checks if ch["score"] < 10]
    out["checks" if all_checks else "weak_checks"] = [
        {"name": ch["name"], "score": ch["score"], "risk": info(ch["name"])["risk"], "reason": (ch.get("reason") or "")[:200]}
        for ch in picked
    ]
    skipped = _inconclusive(raw)
    if skipped:
        out["not_evaluated"] = skipped
    if not all_checks:
        out["note"] = "Weak checks are ordered by priority (risk weight x points lost). Use hardening_plan for fixes or check_details for evidence."
    return out


async def check_details(c: ScorecardClient, repo: str, check: str, commit: str | None = None, max_lines: int = 15, include_info: bool = False) -> dict[str, Any]:
    raw = await c.result(repo, commit)
    want = canonical(check) or check.strip()
    found = next((ch for ch in raw.get("checks", []) if ch.get("name", "").lower() == want.lower()), None)
    if found is None:
        names = ", ".join(sorted(ch.get("name", "") for ch in raw.get("checks", [])))
        raise ScorecardError(f"Check '{check}' not found for {raw.get('repo', {}).get('name', repo)}. Available checks: {names}.")
    meta = info(found["name"])
    lines, total = _lines(found.get("details"), max_lines, warn_only=not include_info)
    out: dict[str, Any] = {
        "repo": (raw.get("repo") or {}).get("name"),
        "check": found["name"],
        "score": found.get("score"),
        "risk": meta["risk"],
        "reason": found.get("reason"),
        "what_it_measures": meta["what"] or (found.get("documentation") or {}).get("short"),
        "evidence": lines,
        "evidence_total": total,
        "evidence_kind": "warnings only" if (not include_info and any(str(d).startswith("Warn") for d in found.get("details") or [])) else "all lines",
        "how_to_improve": meta["fix"] or None,
        "docs": (found.get("documentation") or {}).get("url"),
    }
    if total > len(lines):
        out["note"] = f"Showing {len(lines)} of {total} evidence lines; raise max_lines to see more."
    return out


async def hardening_plan(c: ScorecardClient, repo: str, commit: str | None = None, max_items: int = 8, lines_per_item: int = 4) -> dict[str, Any]:
    raw = await c.result(repo, commit)
    weak = [ch for ch in _scored(raw) if ch["score"] < 10]
    weak.sort(key=lambda ch: (-_priority(ch), ch["name"]))
    out = _header(raw)
    items = []
    for ch in weak[: max(max_items, 0)]:
        meta = info(ch["name"])
        ev, total = _lines(ch.get("details"), lines_per_item)
        items.append(
            {
                "check": ch["name"],
                "score": ch["score"],
                "risk": meta["risk"],
                "reason": (ch.get("reason") or "")[:200],
                "evidence": ev,
                "evidence_total": total,
                "fix": meta["fix"] or None,
                "docs": (ch.get("documentation") or {}).get("url"),
            }
        )
    out["items"] = items
    out["weak_total"] = len(weak)
    if not weak:
        out["note"] = "Every evaluated check scored 10."
    elif len(weak) > len(items):
        out["note"] = f"Showing the top {len(items)} of {len(weak)} weak checks by priority; raise max_items for the rest."
    skipped = _inconclusive(raw)
    if skipped:
        out["not_evaluated"] = skipped
    return out


async def compare_repos(c: ScorecardClient, repos: list[str], checks: list[str] | None = None) -> dict[str, Any]:
    if not repos:
        raise ScorecardError("Provide at least one repository.")
    if len(repos) > MAX_REPOS:
        raise ScorecardError(f"Too many repositories ({len(repos)}); the limit is {MAX_REPOS} per call.")
    seen: dict[str, str] = {}
    for r in repos:
        seen.setdefault(r.strip().lower(), r)
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(r: str) -> tuple[str, dict[str, Any] | None, str | None]:
        async with sem:
            try:
                return r, await c.result(r), None
            except ScorecardError as exc:
                return r, None, str(exc)

    results = await asyncio.gather(*(one(r) for r in seen.values()))
    wanted = None
    if checks:
        wanted = [canonical(x) or x.strip() for x in checks]
    rows, errors = [], []
    for r, raw, err in results:
        if raw is None:
            errors.append({"repo": r, "error": err})
            continue
        scored = {ch["name"]: ch["score"] for ch in _scored(raw)}
        weakest = sorted((ch for ch in _scored(raw) if ch["score"] < 10), key=lambda ch: (-_priority(ch), ch["name"]))[:3]
        row: dict[str, Any] = {
            "repo": (raw.get("repo") or {}).get("name") or r,
            "score": raw.get("score"),
            "rating": rating(raw.get("score")),
            "scanned": (raw.get("date") or "")[:10],
            "weakest": [f"{ch['name']}={ch['score']}" for ch in weakest],
        }
        if wanted:
            row["checks"] = {n: scored.get(n) for n in wanted}
        rows.append(row)
    rows.sort(key=lambda x: (x["score"] is None, x["score"] if x["score"] is not None else 0, x["repo"]))
    out: dict[str, Any] = {"count": len(rows), "repos": rows}
    if rows:
        scores = [x["score"] for x in rows if x["score"] is not None]
        if scores:
            out["lowest"], out["highest"] = min(scores), max(scores)
        out["order"] = "lowest score first"
    if errors:
        out["errors"] = errors
    return out


def list_checks() -> dict[str, Any]:
    rows = [{"check": n, "risk": v["risk"], "measures": v["what"], "fix": v["fix"]} for n, v in CHECKS.items()]
    rows.sort(key=lambda r: (-RISK_WEIGHT[r["risk"]], r["check"]))
    return {
        "scale": "Each check scores 0-10 (-1 means it could not be evaluated). The overall score is a risk-weighted average.",
        "weights": RISK_WEIGHT,
        "checks": rows,
    }
