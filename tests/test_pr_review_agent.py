from __future__ import annotations

from unittest.mock import patch
import urllib.error

from scripts import pr_review_agent as agent
from scripts import pr_comment_agent


def cf(path: str, text: str) -> agent.ChangedFile:
    return agent.ChangedFile(path, text.splitlines(), text, text)


def test_security_finds_secret_and_eval() -> None:
    sample = "password = " + ("x" * 16) + "\n" + "e" + "val(user_input)"
    findings = agent.review_security([cf("app.py", sample)])
    titles = {finding.title for finding in findings}
    assert "Potential generic secret" in titles
    assert "Use of eval" in titles


def test_guidance_finds_missing_tests() -> None:
    findings = agent.review_guidance([cf("app.py", "print('x')")], "Changes must include tests")
    assert findings[0].title == "Tests may be missing"


def test_workflow_finds_missing_controls() -> None:
    workflow = "name: ci\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@main\n"
    findings = agent.review_workflows([cf(".github/workflows/ci.yml", workflow)])
    titles = {finding.title for finding in findings}
    assert "Missing permissions" in titles
    assert "Floating action reference" in titles


def test_infrastructure_finds_generic_iac_and_container_gaps() -> None:
    tf = '''
resource "aws_iam_policy" "bad" { policy = jsonencode({ Action = ["*"], Resource = ["*"] }) }
resource "aws_security_group" "web" { ingress { cidr_blocks = ["0.0.0.0/0"] } }
'''
    dockerfile = "FROM python:latest\nRUN python -m app\n"
    findings = agent.review_infrastructure([cf("main.tf", tf), cf("Dockerfile", dockerfile)])
    titles = {finding.title for finding in findings}
    assert "Wildcard infrastructure access" in titles
    assert "Public network exposure" in titles
    assert "Floating Docker base image" in titles
    assert "Container may run as root" in titles


def test_render_groups_by_severity_and_clean_state() -> None:
    finding_comment = agent.render([], [agent.finding("critical", "Security", "app.py", "Secret", "desc", "rec")])
    clean_comment = agent.render([], [])
    assert "<!-- pr-review-agent -->" in finding_comment
    assert "Critical: 1" in finding_comment
    assert "## Critical" in finding_comment
    assert "No PR review comments needed" in clean_comment


def test_post_updates_existing_comment() -> None:
    commenter = pr_comment_agent.PRCommentAgent(agent.ROOT)
    with patch.object(pr_comment_agent, "event", return_value={"pull_request": {"number": 3}}), patch.dict("os.environ", {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}), patch.object(pr_comment_agent, "github_request") as request:
        request.side_effect = [[{"body": "<!-- pr-review-agent --> old", "url": "https://api.github.com/comment/1"}], {}]
        commenter.post_or_print("<!-- pr-review-agent --> new")
    assert request.call_args_list[1].args[0] == "PATCH"


def test_resolve_previous_review_threads_uses_graphql_when_clean() -> None:
    query_response = {
        "repository": {
            "pullRequest": {
                "reviewThreads": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [{"id": "thread-1", "isResolved": False}, {"id": "thread-2", "isResolved": True}],
                }
            }
        }
    }
    commenter = pr_comment_agent.PRCommentAgent(agent.ROOT)
    with patch.object(pr_comment_agent, "event", return_value={"pull_request": {"number": 3}}), patch.dict("os.environ", {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "PR_REVIEW_AGENT_RESOLVE_THREADS": "true"}), patch.object(pr_comment_agent, "graphql_request") as request:
        request.side_effect = [query_response, {"resolveReviewThread": {"thread": {"id": "thread-1", "isResolved": True}}}]
        assert commenter.resolve_previous_review_threads() == 1
    assert request.call_args_list[1].args[2] == {"threadId": "thread-1"}


def test_should_fail_defaults_to_blocking_when_findings_exist() -> None:
    with patch.dict("os.environ", {}, clear=True):
        assert agent.should_fail([agent.finding("low", "Guidance", "PR", "Thing", "desc", "rec")]) is True
        assert agent.should_fail([]) is False


def test_post_falls_back_on_403_without_raising() -> None:
    error = urllib.error.HTTPError("https://api.github.com", 403, "Forbidden", {}, None)
    error.fp = type("Body", (), {"read": lambda self: b'{"message":"Resource not accessible by integration"}'})()
    commenter = pr_comment_agent.PRCommentAgent(agent.ROOT)
    with patch.object(pr_comment_agent, "event", return_value={"pull_request": {"number": 3}}), patch.dict("os.environ", {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}), patch.object(pr_comment_agent, "github_request", side_effect=error):
        commenter.post_or_print("<!-- pr-review-agent --> body")


def test_code_review_agent_combines_reviewers() -> None:
    sample = "TO" + "DO: fix this before merge" + "\n" + "requests" + ".get(url)"
    findings = agent.CodeReviewAgent().review([cf("app.py", sample)], "")
    titles = {finding.title for finding in findings}
    assert "Unresolved work marker" in titles
    assert "HTTP call without timeout" in titles


def test_pr_comment_agent_posts_and_resolves_only_when_clean() -> None:
    with patch.object(pr_comment_agent.PRCommentAgent, "post_or_print") as post, patch.object(pr_comment_agent.PRCommentAgent, "resolve_previous_review_threads", return_value=2):
        commenter = pr_comment_agent.PRCommentAgent(agent.ROOT)
        commenter.post([], [])
        assert commenter.resolve_when_clean([]) == 2
    post.assert_called_once()
