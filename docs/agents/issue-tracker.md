# Issue tracker: GitHub (fork)

Issues and PRDs for this repo live as GitHub issues on **`janiussyafiq/apisix`** (your fork), not on `apache/apisix`. Use the `gh` CLI for all operations.

This clone has two GitHub remotes (`origin` → fork, `upstream` → `apache/apisix`), so `gh` will not infer the right repo from `git remote -v`. **Always pass `-R janiussyafiq/apisix` explicitly** on every command, otherwise `gh` may prompt or target upstream.

## Conventions

- **Create an issue**: `gh issue create -R janiussyafiq/apisix --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> -R janiussyafiq/apisix --comments`.
- **List issues**: `gh issue list -R janiussyafiq/apisix --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> -R janiussyafiq/apisix --body "..."`
- **Apply / remove labels**: `gh issue edit <number> -R janiussyafiq/apisix --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> -R janiussyafiq/apisix --comment "..."`

If a label doesn't exist yet on the fork, create it on first use with `gh label create "<name>" -R janiussyafiq/apisix --description "..."`.

## Cross-referencing apache/apisix

When work in this fork relates to an upstream Apache issue or PR (e.g. `apache/apisix#13351`), reference it by full `owner/repo#number` form in the body so GitHub auto-links it. Don't move the issue itself to upstream — that's a separate decision the human makes when filing a PR.

## When a skill says "publish to the issue tracker"

Create a GitHub issue on `janiussyafiq/apisix`.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> -R janiussyafiq/apisix --comments`. If the user references an upstream issue (e.g. "the apache 13351 thing"), use `-R apache/apisix` for the read instead.
