#!/usr/bin/env python3
"""Small GitHub PR review agent.

What it does:
- reads every all.md guidance file
- reviews only changed files in the PR diff
- uses a CodeReviewAgent to find guidance, security, workflow, code-quality, and infrastructure issues
- uses a PRCommentAgent to create or update one GitHub PR comment through the GitHub API
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

from scripts.pr_comment_agent import PRCommentAgent

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
        findings.append(finding("medium", "Guidance", "PR", "Tests may be missing", "Project guidance mentions tests, but no test file changed.", "Add tests or explain why this PR does not need them."))
    if re.search(r"\bdocumentation|docs|readme\b", guidance, re.I) and not re.search(r"(^|/)docs?/|readme|\.md$", changed_paths, re.I):
        findings.append(finding("low", "Guidance", "PR", "Documentation may be missing", "Project guidance mentions documentation, but no documentation file changed.", "Update docs or explain why this is internal-only."))
    for raw in guidance.splitlines():
        rule = raw.strip(" -*\t")
        if re.search(r"\b(must|should|required|never|avoid|ensure|include|do not|don't)\b", rule, re.I):
            terms = [word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", rule) if word.lower() not in {"must", "should", "required", "never", "avoid", "ensure", "include", "with", "that", "this", "from", "when"}]
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
                findings.append(finding("critical", "Security", file.path, f"Potential {label}", "Added lines look like they contain a secret.", "Remove it, rotate it if real, and load it from GitHub Secrets or a secret manager."))
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


def review_code_quality(files: list[ChangedFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        text = "\n".join(file.additions)
        if not text:
            continue
        if re.search("TO" + "DO|FIX" + "ME", text, re.I):
            findings.append(finding("info", "Code Quality", file.path, "Unresolved work marker", "Added code contains unfinished work markers.", "Resolve the marker before merge or link it to a tracked follow-up issue."))
        if re.search(r"except\s+Exception\s*:\s*(pass|return None)?", text):
            findings.append(finding("medium", "Code Quality", file.path, "Broad exception handling", "Added code catches a broad exception and may hide failures.", "Catch specific exceptions and log useful context."))
        if re.search(r"requests\.(get|post|put|delete)\([^\n]*(?!timeout\s*=)", text):
            findings.append(finding("medium", "Reliability", file.path, "HTTP call without timeout", "Added HTTP client call appears to omit a timeout.", "Set explicit connect/read timeouts and retry policy where appropriate."))
        if re.search("SEL" + r"ECT .*(%|\.format\(|f['\"])", text, re.I):
            findings.append(finding("high", "Security", file.path, "Possible SQL string interpolation", "Added SQL appears to be built with string interpolation.", "Use parameterized queries or a query builder."))
    return findings


def review_infrastructure(files: list[ChangedFile]) -> list[Finding]:
    findings: list[Finding] = []
    for file in files:
        text = file.content or "\n".join(file.additions)
        if file.path.endswith(".tf"):
            resources = re.findall(r'resource\s+"([^"]+)"', text)
            if resources and re.search(r"(Action|Resource|actions)\s*=\s*\[?\s*\"\*\"", text, re.I):
                findings.append(finding("critical", "Infrastructure", file.path, "Wildcard infrastructure access", "Infrastructure policy appears to allow wildcard action or resource access.", "Scope permissions to the minimum required actions and resources."))
            if resources and "0.0.0.0/0" in text:
                findings.append(finding("high", "Infrastructure", file.path, "Public network exposure", "Infrastructure changes expose a resource to 0.0.0.0/0.", "Restrict CIDRs or document why public access is required."))
            if resources and "tags" not in text and "default_tags" not in text:
                findings.append(finding("low", "Infrastructure", file.path, "Missing resource tags", "Infrastructure resources changed without visible tags/default tags.", "Add ownership, environment, and cost allocation tags."))
        if file.path.endswith((".yml", ".yaml")) and re.search(r"image:\s*[^\s]+:latest\b", text):
            findings.append(finding("medium", "Infrastructure", file.path, "Latest container image tag", "A manifest uses a floating latest image tag.", "Pin images to an immutable digest or explicit version."))
        if file.path.endswith("Dockerfile") or file.path.lower().endswith(".dockerfile"):
            if re.search(r"^\s*FROM\s+[^\s:]+(?=\s|$)|:latest\b", text, re.I | re.M):
                findings.append(finding("medium", "Infrastructure", file.path, "Floating Docker base image", "Docker base image is not pinned to a stable version or digest.", "Pin base images to an explicit version or digest."))
            if not re.search(r"^\s*USER\s+", text, re.I | re.M):
                findings.append(finding("medium", "Infrastructure", file.path, "Container may run as root", "Dockerfile does not set a non-root USER.", "Create and switch to a non-root user before runtime."))
    return findings


class CodeReviewAgent:
    """Reviews changed code and returns actionable findings."""

    def review(self, files: list[ChangedFile], guidance: str) -> list[Finding]:
        findings = (
            review_guidance(files, guidance)
            + review_security(files)
            + review_workflows(files)
            + review_code_quality(files)
            + review_infrastructure(files)
        )
        seen: set[tuple[str, str, str, str]] = set()
        unique: list[Finding] = []
        for item in findings:
            key = (item.severity, item.category, item.file, item.title)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique


def review(files: list[ChangedFile], guidance: str) -> list[Finding]:
    return CodeReviewAgent().review(files, guidance)



def render(guidance_paths: list[Path], findings: list[Finding]) -> str:
    from scripts.pr_comment_agent import render_comment

    return render_comment(ROOT, guidance_paths, findings)

def should_fail(findings: list[Finding]) -> bool:
    if os.getenv("PR_REVIEW_AGENT_FAIL_ON_FINDINGS", "true").lower() not in {"1", "true", "yes"}:
        return False
    return bool(findings)


def main() -> int:
    paths = guidance_files()
    guidance = read_guidance(paths)
    diff = unified_diff()
    files = collect_changed_files(diff)
    findings = CodeReviewAgent().review(files, guidance)
    commenter = PRCommentAgent(ROOT)
    commenter.post(paths, findings)
    if findings:
        print(f"PR review found {len(findings)} issue(s); fix them before merge.", file=sys.stderr)
        return 1 if should_fail(findings) else 0
    resolved = commenter.resolve_when_clean(findings)
    if resolved:
        print(f"Resolved {resolved} previous review thread(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
