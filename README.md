# scorecard-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the [OpenSSF Scorecard](https://scorecard.dev) API. Scorecard scores public repositories from 0 to 10 on supply-chain and repository security practices: branch protection, code review, pinned dependencies, least-privilege workflow tokens, signed releases, known vulnerabilities and more. The public API needs no key.

The Scorecard API has a single read endpoint that returns a large JSON document per repository. This server turns it into task-shaped tools: checks are ordered by risk rather than alphabetically, evidence lines are trimmed to the warnings that explain a score, each weak check comes with a short remediation note and a link to the upstream documentation, and several repositories can be compared in one call.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <this repo> && cd scorecard-mcp
uv sync
uv run scorecard-mcp          # stdio transport
```

Add it to any MCP client that launches stdio servers:

```json
{
  "mcpServers": {
    "scorecard": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/scorecard-mcp", "scorecard-mcp"]
    }
  }
}
```

For HTTP instead of stdio: `MCP_TRANSPORT=streamable-http MCP_HOST=127.0.0.1 MCP_PORT=8000 uv run scorecard-mcp`.

## Tools

All tools are read-only. A repository can be given as `github.com/owner/name`, a full or SSH URL, or just `owner/name` (GitHub is assumed). GitLab repositories use `gitlab.com/group/name`.

| Tool | What it returns |
|---|---|
| `hardening_plan` | The weak checks for a repository in priority order (risk weight times points lost), each with its risk level, the warning lines naming the files and settings behind the score, a remediation note and a docs link. Start here. |
| `repo_score` | Overall score, scan date, scanned commit and the checks below 10, ordered by priority. `all_checks` lists every scored check. |
| `check_details` | Evidence for one check (for example `Token-Permissions` or `Pinned-Dependencies`): reason, warning lines, what it measures, how to improve it. |
| `compare_repos` | Up to 30 repositories ranked lowest first, each with its three highest-priority weak checks and optional per-check columns. Repositories with no stored result are listed under `errors` and do not fail the call. |
| `list_checks` | Reference table of every check with risk level and remediation. No network call. |

An optional `commit` argument fetches a stored result for a specific 40-character commit SHA instead of the latest scan.

## Configuration

All optional environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SCORECARD_BASE_URL` | `https://api.scorecard.dev` | API root (for a mirror or proxy) |
| `SCORECARD_TIMEOUT` | `30` | Request timeout in seconds |
| `SCORECARD_RETRIES` | `2` | Retries on HTTP 429, 502, 503, 504 and timeouts |
| `SCORECARD_CACHE_SECONDS` | `600` | In-process cache of results (the API sends `max-age=600`) |
| `SCORECARD_MAX_CHARS` | `20000` | Responses longer than this are cut with a notice |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |

## Limits

- The public API only returns repositories that Scorecard has already scanned: widely used projects and repositories that publish their own results from CI. Anything else comes back as a clear "no stored result" message. Scanning a private or unlisted repository needs the Scorecard CLI.
- Results are a snapshot. The scan date is included in every response and can be days or weeks old.
- A score of -1 means a check could not be evaluated (for example Branch-Protection when the scan could not read repository settings); those checks are listed under `not_evaluated` and are left out of priorities.
- The risk levels and remediation notes in `list_checks` summarise the upstream documentation; always follow the docs link in a result for the authoritative wording.
- `compare_repos` runs up to 6 requests at once. The Scorecard API does not document rate limits, so the server retries politely but does not queue requests.
- Scorecard measures practices, not security. A high score does not mean a project is free of vulnerabilities.

## Development

```bash
uv sync
uv run pytest
```

Tests mock all HTTP traffic with `respx`; no network access is needed.

## Licence

MIT. Copyright (c) 2026 Ankur Kapuriya.
