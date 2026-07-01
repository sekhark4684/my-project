from __future__ import annotations

from unittest.mock import patch

from scripts import pr_review_agent as agent


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


def test_terraform_finds_aws_and_ecs_gaps() -> None:
    tf = '''
resource "aws_ecs_cluster" "main" { name = "app" }
resource "aws_ecs_service" "svc" { name = "app" }
resource "aws_ecs_task_definition" "task" { family = "app" }
resource "aws_iam_policy" "bad" { policy = jsonencode({ Action = ["*"], Resource = ["*"] }) }
'''
    findings = agent.review_terraform_aws([cf("main.tf", tf)])
    titles = {finding.title for finding in findings}
    assert "Wildcard IAM access" in titles
    assert "ECS cluster insights missing" in titles
    assert "ECS service resilience missing" in titles
    assert "ECS task logging missing" in titles


def test_render_groups_by_severity_and_clean_state() -> None:
    finding_comment = agent.render([], [agent.finding("critical", "Security", "app.py", "Secret", "desc", "rec")])
    clean_comment = agent.render([], [])
    assert "<!-- pr-review-agent -->" in finding_comment
    assert "Critical: 1" in finding_comment
    assert "## Critical" in finding_comment
    assert "No PR review comments needed" in clean_comment


def test_post_updates_existing_comment() -> None:
    with patch.object(agent, "event", return_value={"pull_request": {"number": 3}}), patch.dict("os.environ", {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}), patch.object(agent, "github_request") as request:
        request.side_effect = [[{"body": "<!-- pr-review-agent --> old", "url": "https://api.github.com/comment/1"}], {}]
        agent.post_or_print("<!-- pr-review-agent --> new")
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
    with patch.object(agent, "event", return_value={"pull_request": {"number": 3}}), patch.dict("os.environ", {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "PR_REVIEW_AGENT_RESOLVE_THREADS": "true"}), patch.object(agent, "graphql_request") as request:
        request.side_effect = [query_response, {"resolveReviewThread": {"thread": {"id": "thread-1", "isResolved": True}}}]
        assert agent.resolve_previous_review_threads() == 1
    assert request.call_args_list[1].args[2] == {"threadId": "thread-1"}


def test_should_fail_defaults_to_blocking_when_findings_exist() -> None:
    with patch.dict("os.environ", {}, clear=True):
        assert agent.should_fail([agent.finding("low", "Guidance", "PR", "Thing", "desc", "rec")]) is True
        assert agent.should_fail([]) is False
