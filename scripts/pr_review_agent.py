#!/usr/bin/env python3
"""Small GitHub PR review agent.

What it does:
- reads every all.md guidance file
- reviews only changed files in the PR diff
- adds a few high-value checks: guidance, secrets, unsafe code, workflows, AWS Terraform/ECS
- creates or updates one GitHub PR comment through the GitHub API
- also runs locally by printing the report
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

ROOT = Path(os.getenv("PR_REVIEW_AGENT_REPO_ROOT", Path(__file__).resolve().parents[1])).resolve()
COMMENT_MARKER = "<!-- pr-review-agent -->"
SEVERITIES = ("critical", "high", "medium", "low", "info")
Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class ChangedFile:
    path: str
    additions: list[str]
    diff: str
    content: str


@dataclass(frozen=True)
class Finding:
    severity: Severity
    category: str
    file: str
    title: str
    description: str
    recommendation: str


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True)


def guidance_files() -> list[Path]:
    ignored = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__"}
    return sorted(path for path in ROOT.rglob("all.md") if not ignored.intersection(path.parts))


def read_guidance(files: Iterable[Path]) -> str:
    parts: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if text:
            parts.append(f"## {path.relative_to(ROOT)}\n{text}")
    return "\n\n".join(parts)


def base_ref() -> str:
    if os.getenv("GITHUB_BASE_REF"):
        return f"origin/{os.environ['GITHUB_BASE_REF']}"
    return os.getenv("BASE_SHA") or "HEAD~1"


def unified_diff() -> str:
    try:
        return git(["diff", "--unified=0", f"{base_ref()}...HEAD"])
    except subprocess.CalledProcessError:
        return git(["diff", "--unified=0", "HEAD~1..HEAD"])


def collect_changed_files(diff: str) -> list[ChangedFile]:
    files: list[ChangedFile] = []
    path: str | None = None
    lines: list[str] = []
    additions: list[str] = []
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if path:
                files.append(ChangedFile(path, additions, "\n".join(lines), file_text(path)))
            path, lines, additions = None, [line], []
            continue
        lines.append(line)
        if line.startswith("+++ b/"):
            path = line.removeprefix("+++ b/")
        elif line.startswith("+") and not line.startswith("+++"):
            additions.append(line[1:])
    if path:
        files.append(ChangedFile(path, additions, "\n".join(lines), file_text(path)))
    return files


def file_text(path: str) -> str:
    target = ROOT / path
    if not target.exists() or target.is_dir():
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def finding(severity: Severity, category: str, file: str, title: str, description: str, recommendation: str) -> Finding:
    return Finding(severity, category, file, title, description, recommendation)


def review_guidance(files: list[ChangedFile], guidance: str) -> list[Finding]:
    if not guidance or not files:
        return []
    findings: list[Finding] = []
    changed_paths = "\n".join(file.path for file in files)
    added = "\n".join(line for file in files for line in file.additions)
    if re.search(r"\btest(s|ing)?\b", guidance, re.I) and not re.search(r"(^|/)(tests?|spec|__tests__)/|(_test|\.test|\.spec)\.", changed_paths, re.I):
        findings.append(finding("medium", "Guidance", "PR", "Tests may be missing", "Project guidance mentions tests, but no test file changed.", "Add tests or explain why this PR does not need tests."))
    if re.search(r"\bdocumentation|docs|readme\b", guidance, re.I) and not re.search(r"(^|/)docs?/|readme|\.md$", changed_paths, re.I):
        findings.append(finding("low", "Guidance", "PR", "Documentation may be missing", "Project guidance mentions documentation, but no documentation file changed.", "Update docs or explain why this PR does not need documentation."))
    for raw in guidance.splitlines():
        rule = raw.strip(" -*\t")
        if re.search(r"\b(must|should|required|never|avoid|ensure|include|do not|don't)\b", rule, re.I):
            terms = [word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", rule) if word.lower() not in {"must", "should", "required", "never", "avoid", "ensure", "include", "with", "this", "that", "from", "file", "code", "when", "only", "also", "does"}]
            if terms and not any(term in added.lower() for term in terms[:3]):
                findings.append(finding("info", "Guidance", "all.md", "Verify project rule", f"Please verify this guidance is satisfied: `{rule}`", "Update the PR or reply why the rule does not apply."))
    return findings[:10]


def review_security(files: list[ChangedFile]) -> list[Finding]:
    secret_patterns = (
        ("AWS access key", r"AKIA[0-9A-Z]{16}"),
        ("SSH private key", r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        ("GitHub token", r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        ("JWT", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        ("generic secret", r"(?i)(api[_-]?key|secret|token|password|credential)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=\-]{12,}"),
    )
    risky_code = (
        ("high", "Use of eval", r"\b" + "eval" + r"\s*\(", "Replace dynamic code execution with safe parsing or explicit dispatch."),
        ("high", "subprocess shell=True", r"subprocess\.[A-Za-z_]+\([^\n]*shell\s*=\s*True", "Pass arguments as a list and keep shell=False."),
        ("high", "Unsafe pickle load", r"\bpickle\.loads?\s*\(", "Use JSON or another safe format for untrusted data."),
        ("high", "Unsafe yaml.load", r"yaml\.load\s*\(", "Use yaml.safe_load()."),
    )
    findings: list[Finding] = []
    for file in files:
        text = "\n".join(file.additions)
        for label, pattern in secret_patterns:
            if re.search(pattern, text):
                findings.append(finding("critical", "Security", file.path, f"Potential {label}", "Added lines look like they contain a secret.", "Remove it, rotate it if real, and load it from GitHub secrets."))
                break
        for severity, title, pattern, recommendation in risky_code:
            if re.search(pattern, text, re.I):
                findings.append(finding(severity, "Security", file.path, title, "Added code uses a dangerous security-sensitive pattern.", recommendation))  # type: ignore[arg-type]
    return findings


def review_workflows(files: list[ChangedFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if not (file.path.startswith(".github/workflows/") and file.path.endswith((".yml", ".yaml"))):
            continue
        text = file.content or "\n".join(file.additions)
        if "permissions:" not in text:
            findings.append(finding("high", "GitHub Actions", file.path, "Missing permissions", "Workflow does not declare explicit permissions.", "Add least-privilege permissions."))
        if "timeout-minutes:" not in text:
            findings.append(finding("medium", "GitHub Actions", file.path, "Missing timeout", "Workflow jobs can run indefinitely.", "Set timeout-minutes for each job."))
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if re.search(r"@(main|master|latest)$", action) or "@" not in action:
                findings.append(finding("medium", "GitHub Actions", file.path, "Floating action reference", f"`{action}` is not pinned to a stable version.", "Pin actions to a trusted major version or commit SHA."))
    return findings


def review_terraform_aws(files: list[ChangedFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        if not file.path.endswith(".tf"):
            continue
        text = file.content or "\n".join(file.additions)
        resources = re.findall(r'resource\s+"(aws_[^"]+)"', text)
        if not resources:
            continue
        if re.search(r"(Action|Resource|actions)\s*=\s*\[?\s*\"\*\"", text, re.I):
            findings.append(finding("critical", "AWS Terraform", file.path, "Wildcard IAM access", "IAM policy appears to allow wildcard action or resource access.", "Scope IAM actions and resources to the minimum required."))
        if "0.0.0.0/0" in text and re.search(r"aws_security_group|ingress", text):
            findings.append(finding("high", "AWS Terraform", file.path, "Public security group ingress", "Security group ingress appears open to the internet.", "Restrict CIDRs or document why public access is required."))
        if "tags" not in text and "default_tags" not in text:
            findings.append(finding("low", "AWS Terraform", file.path, "Missing AWS tags", "AWS resources changed without visible tags/default_tags.", "Add ownership, environment, and cost allocation tags."))
        if re.search(r"aws_(s3_bucket|db_instance|rds_cluster|dynamodb_table|ebs_volume|efs_file_system|secretsmanager_secret|lambda_function)", text) and not re.search(r"kms|encrypted\s*=\s*true", text):
            findings.append(finding("medium", "AWS Terraform", file.path, "Encryption or recovery not evident", "Stateful/sensitive AWS resources changed without visible encryption or recovery settings.", "Enable encryption and configure backup/recovery."))
        if "aws_ecs_cluster" in resources and not re.search(r"containerInsights|container_insights", text):
            findings.append(finding("medium", "AWS Terraform", file.path, "ECS cluster insights missing", "ECS cluster changed without visible Container Insights.", "Enable Container Insights for better observability."))
        if "aws_ecs_service" in resources and not re.search(r"deployment_circuit_breaker|desired_count|aws_appautoscaling_target", text):
            findings.append(finding("medium", "AWS Terraform", file.path, "ECS service resilience missing", "ECS service changed without visible rollback or capacity policy.", "Add deployment_circuit_breaker and auto-scaling targets."))
        if "aws_ecs_task_definition" in resources and not re.search(r"logConfiguration|awslogs|firelens", text):
            findings.append(finding("medium", "AWS Terraform", file.path, "ECS task logging missing", "ECS task definition changed without container log configuration.", "Send task logs to CloudWatch or another logging backend."))
    return findings


def review(files: list[ChangedFile], guidance: str) -> list[Finding]:
    findings = review_guidance(files, guidance) + review_security(files) + review_workflows(files) + review_terraform_aws(files)
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = (item.severity, item.category, item.file, item.title)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def render(guidance_paths: list[Path], findings: list[Finding]) -> str:
    paths = ", ".join(str(path.relative_to(ROOT)) for path in guidance_paths) or "none"
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
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"},
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


def post_or_print(comment: str) -> None:
    context = github_context()
    if not context:
        print(comment)
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
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        raise


def resolve_previous_review_threads() -> int:
    """Resolve existing review threads after the agent reports a clean PR.

    This uses GitHub GraphQL because regular issue comments cannot be resolved.
    It is intentionally called only when no findings remain, so unresolved human
    feedback is not hidden while the PR still has known problems.
    """
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


def should_fail(findings: list[Finding]) -> bool:
    if os.getenv("PR_REVIEW_AGENT_FAIL_ON_FINDINGS", "true").lower() not in {"1", "true", "yes"}:
        return False
    return bool(findings)


def main() -> int:
    paths = guidance_files()
    guidance = read_guidance(paths)
    diff = unified_diff()
    files = collect_changed_files(diff)
    findings = review(files, guidance)
    post_or_print(render(paths, findings))
    if findings:
        print(f"PR review found {len(findings)} issue(s); fix them before merge.", file=sys.stderr)
        return 1 if should_fail(findings) else 0
    resolved = resolve_previous_review_threads()
    if resolved:
        print(f"Resolved {resolved} previous review thread(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
