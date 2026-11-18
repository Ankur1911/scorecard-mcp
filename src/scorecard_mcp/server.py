"""MCP server exposing the OpenSSF Scorecard API as a small set of task-shaped tools."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import tools
from .client import ScorecardClient, ScorecardError

Repo = Annotated[
    str,
    Field(description="Repository as 'github.com/owner/name', a full URL, or just 'owner/name' (GitHub assumed). GitLab: 'gitlab.com/group/name'."),
]
Commit = Annotated[str | None, Field(description="Optional full 40-character commit SHA to fetch an older stored result. Omit for the latest scan.")]

MAX_CHARS = 20000
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True, idempotent_hint=True)

client = ScorecardClient()
mcp = MCPServer(
    "scorecard",
    instructions=(
        "Look up OpenSSF Scorecard results (supply-chain and repository security checks scored 0-10) for public "
        "GitHub and GitLab repositories. Start with hardening_plan for what to fix first, repo_score for a quick "
        "read, or compare_repos to rank several repositories. Results come from the public Scorecard API, which "
        "only has repositories that Scorecard scans; they are read-only and need no credentials."
    ),
)


def render(data: Any) -> str:
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    limit = int(os.environ.get("SCORECARD_MAX_CHARS", MAX_CHARS))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated: response was {len(text)} characters; use a smaller limit or a narrower tool]"


async def run(coro: Any) -> str:
    try:
        return render(await coro)
    except ScorecardError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="repo_score",
    description=(
        "Overall OpenSSF Scorecard score (0-10) for one repository, when it was scanned, and the checks that "
        "did not score 10, ordered by priority (risk weight times points lost). Use all_checks to include the "
        "checks that passed. For fixes and evidence use hardening_plan or check_details."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def repo_score(
    repo: Repo, commit: Commit = None, all_checks: Annotated[bool, Field(description="List every scored check, not just the weak ones.")] = False
) -> str:
    return await run(tools.repo_score(client, repo, commit, all_checks))


@mcp.tool(
    name="hardening_plan",
    description=(
        "Prioritised list of what to fix in a repository's supply-chain posture: each weak check with its risk "
        "level, the specific files and settings behind the score (warning lines), and a short remediation note "
        "with a docs link. One call replaces fetching the score and then each check separately."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def hardening_plan(
    repo: Repo,
    commit: Commit = None,
    max_items: Annotated[int, Field(description="Maximum weak checks to include.", ge=1, le=30)] = 8,
    lines_per_item: Annotated[int, Field(description="Evidence lines per check.", ge=0, le=30)] = 4,
) -> str:
    return await run(tools.hardening_plan(client, repo, commit, max_items, lines_per_item))


@mcp.tool(
    name="check_details",
    description=(
        "Evidence for one Scorecard check on one repository (for example Token-Permissions, Pinned-Dependencies, "
        "Branch-Protection, Dangerous-Workflow): score, reason, the warning lines naming files and settings, "
        "what the check measures and how to improve it. Check names are case-insensitive."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def check_details(
    repo: Repo,
    check: Annotated[str, Field(description="Check name such as 'Pinned-Dependencies'. See list_checks for all names.")],
    commit: Commit = None,
    max_lines: Annotated[int, Field(description="Maximum evidence lines to return.", ge=1, le=100)] = 15,
    include_info: Annotated[bool, Field(description="Also include passing 'Info' lines, not only warnings.")] = False,
) -> str:
    return await run(tools.check_details(client, repo, check, commit, max_lines, include_info))


@mcp.tool(
    name="compare_repos",
    description=(
        "Rank up to 30 repositories by Scorecard score, lowest first, each with its three highest-priority weak "
        "checks. Repositories that have no stored result are reported in 'errors' without failing the call. "
        "Pass 'checks' to add a column for specific checks, for example a dependency list's Pinned-Dependencies."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def compare_repos(
    repos: Annotated[list[str], Field(description="Repositories to compare, each as for repo_score.", min_length=1, max_length=30)],
    checks: Annotated[list[str] | None, Field(description="Optional check names to show as per-repo columns.")] = None,
) -> str:
    return await run(tools.compare_repos(client, repos, checks))


@mcp.tool(
    name="list_checks",
    description="Reference list of all Scorecard checks with risk level, what each measures and how to improve it. No network call.",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False, idempotent_hint=True),
    structured_output=False,
)
async def list_checks() -> str:
    return render(tools.list_checks())


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper())
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run("stdio")
    else:
        mcp.run(transport, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8000")))


if __name__ == "__main__":
    main()
