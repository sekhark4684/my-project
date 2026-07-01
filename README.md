# my-project

## GitHub PR Review Agent

This repository includes a small PR review agent that can run locally or in GitHub Actions.

```bash
python3 scripts/pr_review_agent.py
```

The agent intentionally stays lightweight while following a clear merge workflow:

1. Review the PR diff and read every `all.md` guidance file.
2. Post or update one PR review summary comment through the GitHub API using the `<!-- pr-review-agent -->` marker.
3. Fail the workflow when findings exist so the PR is not merged with known review issues.
4. When the PR is clean, resolve previous GitHub review threads through the GitHub GraphQL API.

Current checks focus on high-value review feedback:

- Project guidance from `all.md`, including missing tests or docs when guidance asks for them
- Potential secrets and unsafe code patterns
- GitHub Actions workflow hygiene, such as permissions, timeouts, and floating action references
- AWS Terraform checks, including IAM wildcards, public security groups, tags, encryption/recovery, and ECS cluster/service/task logging and resilience gaps

Environment flags:

- `PR_REVIEW_AGENT_FAIL_ON_FINDINGS=true` blocks merge by returning a non-zero exit code when findings exist.
- `PR_REVIEW_AGENT_RESOLVE_THREADS=true` resolves previous review threads only after the current review has no findings.

The agent does not rewrite PR source code automatically. It makes the code “clear before merge” by blocking the workflow until reported findings are fixed, then clearing previous review threads after a clean run.

### Why the agent may not start on a PR

If this workflow is being introduced by the same PR, GitHub may not run it until the workflow file exists on the target/default branch. After this PR is merged, later PRs will trigger it automatically.

The workflow uses `pull_request_target` so the token can post/update PR comments and resolve review threads. To avoid executing untrusted fork changes with that token, it checks out trusted agent code separately under `agent/` and checks out the PR source under `pr/` only for analysis. For same-repository PRs, it can run the PR copy of the agent so fixes to the agent are tested before merge; fork PRs continue to use the trusted base copy.
