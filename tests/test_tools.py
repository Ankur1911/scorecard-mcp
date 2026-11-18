import json

import httpx
import pytest
import respx
from mcp import Client

from scorecard_mcp import server, tools
from scorecard_mcp.client import ScorecardError, parse_repo

BASE = "https://api.scorecard.dev"
SHA = "a" * 40


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("SCORECARD_RETRY_DELAY", "0")
    monkeypatch.delenv("SCORECARD_BASE_URL", raising=False)
    monkeypatch.delenv("SCORECARD_MAX_CHARS", raising=False)
    server.client.clear_cache()
    yield
    server.client.clear_cache()


async def call(tool, args=None):
    async with Client(server.mcp) as c:
        return await c.call_tool(tool, args or {})


def text(result):
    return "".join(x.text for x in result.content)


def data(result):
    return json.loads(text(result))


def check(name, score, reason="r", details=None):
    return {
        "name": name,
        "score": score,
        "reason": reason,
        "details": details,
        "documentation": {"url": f"https://example.test/docs#{name.lower()}", "short": f"short {name}"},
    }


def doc(name="github.com/acme/widget", score=6.1, checks=None):
    return {
        "date": "2026-11-16T09:03:40Z",
        "repo": {"name": name, "commit": SHA},
        "scorecard": {"version": "v5.6.0", "commit": "b" * 40},
        "score": score,
        "checks": checks
        if checks is not None
        else [
            check("Dangerous-Workflow", 10, "none"),
            check("License", 0, "no license"),
            check(
                "Token-Permissions",
                0,
                "excessive permissions",
                [
                    "Info: topLevel 'contents' permission set to 'read': .github/workflows/a.yml:1",
                    "Warn: no topLevel permission defined: .github/workflows/b.yml:1",
                    "Warn: jobLevel 'checks' permission set to 'write': .github/workflows/c.yml:9",
                ],
            ),
            check("Pinned-Dependencies", 5, "some unpinned", ["Warn: action not pinned: .github/workflows/b.yml:12"]),
            check("Code-Review", 2, "3/13 approved"),
            check("Fuzzing", -1, "internal error"),
            check("Maintained", 10, "active"),
        ],
    }


def test_parse_repo_forms():
    assert parse_repo("github.com/a/b") == ("github.com", "a", "b")
    assert parse_repo("https://github.com/a/b.git") == ("github.com", "a", "b")
    assert parse_repo("a/b") == ("github.com", "a", "b")
    assert parse_repo("git@github.com:a/b.git") == ("github.com", "a", "b")
    assert parse_repo("https://gitlab.com/grp/proj/") == ("gitlab.com", "grp", "proj")
    with pytest.raises(ScorecardError):
        parse_repo("justaname")


async def test_list_tools_all_read_only():
    async with Client(server.mcp) as c:
        listed = await c.list_tools()
    assert {t.name for t in listed.tools} == {"repo_score", "hardening_plan", "check_details", "compare_repos", "list_checks"}
    assert all(t.annotations.read_only_hint for t in listed.tools)
    assert all(t.description for t in listed.tools)


@respx.mock
async def test_repo_score_orders_by_priority_and_skips_inconclusive():
    respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    out = data(await call("repo_score", {"repo": "acme/widget"}))
    assert out["score"] == 6.1 and out["scanned"] == "2026-11-16" and out["rating"] == "fair"
    names = [c["name"] for c in out["weak_checks"]]
    # Token-Permissions (High, 0) > Code-Review (High, 2) > License? 2.5*10=25 vs Pinned 5*5=25 vs Code-Review 7.5*8=60
    assert names[0] == "Token-Permissions" and names[1] == "Code-Review"
    assert "Dangerous-Workflow" not in names and "Fuzzing" not in names
    assert out["not_evaluated"] == ["Fuzzing"]
    assert out["weak_checks"][0]["risk"] == "High"


@respx.mock
async def test_repo_score_all_checks():
    respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    out = data(await call("repo_score", {"repo": "github.com/acme/widget", "all_checks": True}))
    assert "weak_checks" not in out
    assert {c["name"] for c in out["checks"]} >= {"Dangerous-Workflow", "Maintained"}
    assert out["checks_scored"] == 6


@respx.mock
async def test_hardening_plan_trims_to_warnings_and_adds_fix():
    respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    out = data(await call("hardening_plan", {"repo": "acme/widget", "max_items": 2}))
    first = out["items"][0]
    assert first["check"] == "Token-Permissions"
    assert all(line.startswith("Warn") for line in first["evidence"])
    assert first["evidence_total"] == 2
    assert "permissions" in first["fix"].lower()
    assert first["docs"].startswith("https://example.test")
    assert len(out["items"]) == 2 and out["weak_total"] == 4
    assert "Showing the top 2 of 4" in out["note"]


@respx.mock
async def test_hardening_plan_clean_repo():
    respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc(checks=[check("License", 10)], score=10))
    out = data(await call("hardening_plan", {"repo": "acme/widget"}))
    assert out["items"] == [] and "scored 10" in out["note"]


@respx.mock
async def test_check_details_case_insensitive_and_include_info():
    respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    out = data(await call("check_details", {"repo": "acme/widget", "check": "token-permissions"}))
    assert out["check"] == "Token-Permissions" and out["evidence_total"] == 2 and out["evidence_kind"] == "warnings only"
    full = data(await call("check_details", {"repo": "acme/widget", "check": "Token_Permissions", "include_info": True}))
    assert full["evidence_total"] == 3 and full["evidence_kind"] == "all lines"
    capped = data(await call("check_details", {"repo": "acme/widget", "check": "Token-Permissions", "max_lines": 1}))
    assert len(capped["evidence"]) == 1 and "Showing 1 of 2" in capped["note"]


@respx.mock
async def test_check_details_unknown_check_lists_available():
    respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    result = await call("check_details", {"repo": "acme/widget", "check": "Nope"})
    assert result.is_error and "Available checks" in text(result) and "License" in text(result)


@respx.mock
async def test_not_scanned_message():
    respx.get(f"{BASE}/projects/github.com/nobody/nothing").respond(404)
    result = await call("repo_score", {"repo": "nobody/nothing"})
    assert result.is_error and "No Scorecard result stored" in text(result)


@respx.mock
async def test_bad_commit_rejected_without_http_call():
    route = respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    result = await call("repo_score", {"repo": "acme/widget", "commit": "xyz"})
    assert result.is_error and "40-character" in text(result)
    assert not route.called


@respx.mock
async def test_commit_is_sent_as_query_param():
    route = respx.get(f"{BASE}/projects/github.com/acme/widget", params={"commit": SHA}).respond(200, json=doc())
    out = data(await call("repo_score", {"repo": "acme/widget", "commit": SHA}))
    assert route.called and out["commit"] == SHA


@respx.mock
async def test_cache_avoids_second_request():
    route = respx.get(f"{BASE}/projects/github.com/acme/widget").respond(200, json=doc())
    await call("repo_score", {"repo": "acme/widget"})
    await call("hardening_plan", {"repo": "https://github.com/acme/widget.git"})
    assert route.call_count == 1


@respx.mock
async def test_compare_repos_ranks_dedupes_and_reports_errors():
    respx.get(f"{BASE}/projects/github.com/a/low").respond(200, json=doc("github.com/a/low", 3.0))
    respx.get(f"{BASE}/projects/github.com/b/high").respond(200, json=doc("github.com/b/high", 9.1, [check("Pinned-Dependencies", 10)]))
    respx.get(f"{BASE}/projects/github.com/c/missing").respond(404)
    out = data(await call("compare_repos", {"repos": ["b/high", "a/low", "A/Low", "c/missing"], "checks": ["pinned-dependencies"]}))
    assert [r["repo"] for r in out["repos"]] == ["github.com/a/low", "github.com/b/high"]
    assert out["lowest"] == 3.0 and out["highest"] == 9.1
    assert out["repos"][0]["checks"] == {"Pinned-Dependencies": 5}
    assert out["repos"][1]["weakest"] == []
    assert out["repos"][0]["weakest"][0] == "Token-Permissions=0"
    assert out["errors"][0]["repo"] == "c/missing"


@respx.mock
async def test_compare_repos_limit():
    result = await call("compare_repos", {"repos": [f"o/r{i}" for i in range(31)]})
    assert result.is_error


@respx.mock
async def test_retry_on_503_then_success():
    route = respx.get(f"{BASE}/projects/github.com/acme/widget").mock(side_effect=[httpx.Response(503), httpx.Response(200, json=doc())])
    out = data(await call("repo_score", {"repo": "acme/widget"}))
    assert out["score"] == 6.1 and route.call_count == 2


@respx.mock
async def test_rate_limit_and_422_messages(monkeypatch):
    monkeypatch.setenv("SCORECARD_RETRIES", "0")
    respx.get(f"{BASE}/projects/github.com/a/limited").respond(429)
    assert "Rate limited" in text(await call("repo_score", {"repo": "a/limited"}))
    respx.get(f"{BASE}/projects/github.com/a/odd").respond(422, text='{"code":605}')
    r = await call("repo_score", {"repo": "a/odd"})
    assert r.is_error and "422" in text(r)


@respx.mock
async def test_timeout_message(monkeypatch):
    monkeypatch.setenv("SCORECARD_RETRIES", "0")
    respx.get(f"{BASE}/projects/github.com/a/slow").mock(side_effect=httpx.ReadTimeout("slow"))
    r = await call("repo_score", {"repo": "a/slow"})
    assert r.is_error and "timed out" in text(r)


@respx.mock
async def test_custom_base_url_and_truncation(monkeypatch):
    monkeypatch.setenv("SCORECARD_BASE_URL", "https://mirror.test/")
    monkeypatch.setenv("SCORECARD_MAX_CHARS", "200")
    big = doc(checks=[check(f"Check-{i}", 0, "x" * 150) for i in range(20)])
    respx.get("https://mirror.test/projects/github.com/acme/widget").respond(200, json=big)
    out = text(await call("repo_score", {"repo": "acme/widget"}))
    assert "[truncated:" in out


async def test_list_checks_no_network():
    out = data(await call("list_checks"))
    names = [c["check"] for c in out["checks"]]
    assert out["checks"][0]["risk"] == "Critical" and "Token-Permissions" in names
    assert all(c["fix"] for c in out["checks"])


def test_priority_helpers():
    assert tools.rating(9) == "strong" and tools.rating(2) == "poor" and tools.rating(None) == "unknown"
    assert tools._priority({"name": "Dangerous-Workflow", "score": 0}) > tools._priority({"name": "Code-Review", "score": 0})
    assert tools._priority({"name": "Brand-New-Check", "score": 0}) == 50.0
