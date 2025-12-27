---
description: Best practices for interacting with GitHub efficiently
---

1. **Check for GH CLI**: Always verify if the `gh` tool is available using `gh --version`.
2. **Prioritize CLI for PRs/Issues**:
    - Use `gh pr view <number> --json title,body,author,files,comments` for structured context.
    - Use `gh pr diff <number>` to get the full diff.
    - Use `gh issue view <number>` for issue details.
3. **Use Direct Diff/Patch URLs**:
    - If CLI is not available or for quick commit checks, use `curl -L <URL>.diff` or `curl -L <URL>.patch`.
    - This is significantly more efficient than browser scraping.
4. **Avoid Browser Subagent for Code/Metadata**:
    - Only use the `browser_subagent` if you need to see rendered UI, screenshots, or if programmatic access is blocked/unavailable.
5. **Bundle Context**:
    - When reviewing a PR, always try to grab the PR description and discussion comments, as they provide critical "why" context.
6. **Refresh for Action Status**:
    - When checking the status of GitHub Actions via the browser, always **refresh the page** or navigate to it again if you've been waiting for a run to complete. The UI may not always update live for the `browser_subagent`.
