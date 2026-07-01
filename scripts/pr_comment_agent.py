#!/usr/bin/env python3
"""Agent responsible for posting PR review results and resolving threads."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

COMMENT_MARKER = "<!-- pr-review-agent -->"
SEVERITIES = ("critical", "high", "medium", "low", "info")


def render_comment(root: Path, guidance_paths: list[Path], findings: list[Any]) -> str:
    paths = ", ".join(str(path.relative_to(root)) for path in guidance_paths) or "none"
    counts = {severity: sum(1 for item in findings if item.severity == severity) for severity in SEVERITIES}
    score = max(0, 100 - sum({"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 1}[item.severity] for item in findings))
    lines = [COMMENT_MARKER, "# PR Review Summary", "", f"Overall Score: {score}/100", f"Guidance files: {paths}", ""]
    lines += [f"{severity.title()}: {counts[severity]}" for severity in SEVERITIES]
    if not findings:
        return "\n".join(lines + ["", "No PR review comments needed for the current diff."])
    for severity in SEVERITIES:
        items = [item for item in findings if item.severity == severity]
        if not items:
            continue
        lines += ["", f"## {severity.title()}"]
        for item in items:
            lines += ["", f"### {item.category}: {item.title}", f"**File:** `{item.file}`", "", item.description, "", f"**Recommendation:** {item.recommendation}"]
    return "\n".join(lines)


def event() -> dict:
    path = os.getenv("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def github_context() -> tuple[str, str, int] | None:
    token, repo, payload = os.getenv("GITHUB_TOKEN"), os.getenv("GITHUB_REPOSITORY"), event()
    number = payload.get("pull_request", {}).get("number") or payload.get("number") if payload else None
    if token and repo and number:
        return token, repo, int(number)
    return None


def github_request(method: str, url: str, token: str, body: dict | None = None) -> object:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode("utf-8")
        return json.loads(text) if text else {}


def graphql_request(token: str, query: str, variables: dict) -> dict:
    result = github_request("POST", "https://api.github.com/graphql", token, {"query": query, "variables": variables})
    if not isinstance(result, dict):
        return {}
    if result.get("errors"):
        raise RuntimeError(result["errors"])
    return result.get("data", {}) if isinstance(result.get("data"), dict) else {}


def write_step_summary(comment: str) -> None:
    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(comment + "\n", encoding="utf-8")


class PRCommentAgent:
    """Posts reviewed PR results and resolves old review threads after a clean run."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def post(self, guidance_paths: list[Path], findings: list[Any]) -> None:
        self.post_or_print(render_comment(self.root, guidance_paths, findings))

    def post_or_print(self, comment: str) -> None:
        context = github_context()
        if not context:
            print(comment)
            write_step_summary(comment)
            return
        token, repo, number = context
        url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"
        try:
            comments = github_request("GET", url, token)
            existing = next((item for item in comments if COMMENT_MARKER in item.get("body", "")), None) if isinstance(comments, list) else None
            if existing:
                github_request("PATCH", existing["url"], token, {"body": comment})
                print(f"Updated PR review comment: {existing['url']}")
            else:
                created = github_request("POST", url, token, {"body": comment})
                print(f"Posted PR review comment: {created.get('html_url', url) if isinstance(created, dict) else url}")
        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            print(details, file=sys.stderr)
            if exc.code == 403:
                print("Warning: GitHub token cannot write PR comments; wrote review to job summary instead.", file=sys.stderr)
                print(comment)
                write_step_summary(comment)
                return
            raise

    def resolve_when_clean(self, findings: list[Any]) -> int:
        if findings:
            return 0
        return self.resolve_previous_review_threads()

    def resolve_previous_review_threads(self) -> int:
        if os.getenv("PR_REVIEW_AGENT_RESOLVE_THREADS", "true").lower() not in {"1", "true", "yes"}:
            return 0
        context = github_context()
        if not context:
            return 0
        token, repo, number = context
        owner, name = repo.split("/", 1)
        query = """
        query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
          repository(owner: $owner, name: $name) {
            pullRequest(number: $number) {
              reviewThreads(first: 100, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                nodes { id isResolved }
              }
            }
          }
        }
        """
        mutation = """
        mutation($threadId: ID!) {
          resolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } }
        }
        """
        resolved = 0
        cursor = None
        while True:
            data = graphql_request(token, query, {"owner": owner, "name": name, "number": number, "cursor": cursor})
            threads = data.get("repository", {}).get("pullRequest", {}).get("reviewThreads", {})
            for node in threads.get("nodes", []) or []:
                if not node.get("isResolved"):
                    graphql_request(token, mutation, {"threadId": node["id"]})
                    resolved += 1
            page = threads.get("pageInfo", {})
            if not page.get("hasNextPage"):
                return resolved
            cursor = page.get("endCursor")
