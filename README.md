# oy-policies

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aljoshare/oy-policies/badge)](https://scorecard.dev/viewer/?uri=github.com/aljoshare/oy-policies)

Official policy collection for [oy](https://github.com/aljoshare/oy) — a CLI tool that scans Markdown files for harmful or malicious instructions using OPA Rego policies. These policies are purpose-built for the Markdown files that define AI agent behavior:

- **Skills** — `.claude/skills/*/SKILL.md` and equivalent files loaded by agents at runtime
- **Commands** — `.claude/commands/*.md` slash-command definitions
- **Agent specs** — `AGENT.md` and project-level agent configuration files
- **Agent.md files** — `CLAUDE.md`, `AGENTS.md`, and other root-level AI instruction files

## CI

| Workflow | Trigger | What it does |
|---|---|---|
| `fmt.yml` | push / PR | Runs `opa fmt --fail .` — fails if any `.rego` file is not formatted |

## Requirements

- [oy](https://github.com/aljoshare/oy) — to use these policies for scanning
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) — to run the Rego unit tests (`opa test`)

## Quick start

```bash
# Install oy
go install github.com/aljoshare/oy@latest

# Register this repository
oy repo add github.com/aljoshare/oy-policies

# Scan all Skills, Commands, and Agent.md files in a project
oy scan .claude/
oy scan CLAUDE.md AGENT.md
```

## Usage

Register this repository with `oy`:

```bash
oy repo add github.com/aljoshare/oy-policies
```

Policies are cloned locally and loaded automatically on every `oy scan` run. To see where they are cached locally:

```bash
oy repo list
```

## Policies

| File | Detects |
|---|---|
| `prompt_injection.rego` | Instruction overrides (`ignore previous instructions`, system prompt hijacking), context/memory poisoning, invisible Unicode injection (zero-width spaces, bidi overrides) — including techniques used in real attacks against GitHub Copilot and Cursor (2025) |
| `jailbreak.rego` | DAN/AIM/BISH/STAN personas, safety bypass framing, hypothetical/fictional framing (89.6% ASR documented 2025), FlipAttack decode-and-execute (81% ASR documented 2025) |
| `harmful_commands.rego` | Destructive shell commands (`rm -rf /`, fork bombs, disk wipers), privilege escalation (CVE-2025-32463/32462 patterns), persistence attacks (SSH key injection, cron backdoors, shell profile poisoning), supply chain attacks |
| `exfiltration.rego` | Sensitive file reads (`~/.ssh`, `~/.aws`, `.env`), credential/key exposure requests, env var dumping, pipe-to-shell (`curl … \| bash`), image-URL exfiltration (CamoLeak 2025) |
| `social_engineering.rego` | Classic phishing patterns, agent-targeted urgency/authority framing (OWASP LLM Top 10 2025, Lakera research), false-context misdirection (sandbox framing) |
| `tool_poisoning.rego` | Tool/skill invocation abuse (bash, file write, HTTP, browser tools), MCP tool poisoning via hidden HTML comments — Invariant Labs found 5.5% of public MCP servers contain poisoned metadata (2025) |

## Running tests

Each policy file has a companion `*_test.rego` with [OPA unit tests](https://www.openpolicyagent.org/docs/latest/policy-testing/).

**Install OPA**

```bash
# macOS
brew install opa

# Linux / others — download from https://github.com/open-policy-agent/opa/releases
# or via Go
go install github.com/open-policy-agent/opa@latest
```

**Run tests**

```bash
opa test .
opa test -v .    # verbose output
```

If you have [task](https://taskfile.dev) installed:

```bash
task            # run all tests (default)
task test:verbose
task fmt        # format .rego files with opa fmt
task check      # syntax check without running tests
```

Run `task --list` to see all available tasks.

## Writing policies

All policies must follow these conventions or `oy` will not evaluate them correctly.

**Package declaration** (required in every file):

```rego
package oy

import rego.v1
```

**METADATA** (required on every rule) — `oy` skips any `deny` rule that lacks a `# METADATA` block with a `title` and prints a warning to stderr. The `description` field is optional but recommended; it appears in `oy list` output.

```rego
# METADATA
# title: My Rule Title
# description: One-line description of what this rule detects.
```

**Violation rule** — `msg` in `deny contains msg` is unified with the value assigned inside the rule body:

```rego
# METADATA
# title: My Rule Title
# description: Detects pattern one and pattern two in agent files.
deny contains msg if {
    patterns := [
        "pattern one",
        "pattern two",
    ]
    pattern := patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("descriptive label: %q", [pattern])
}
```

**Input fields available to every rule:**

| Field | Type | Description |
|---|---|---|
| `input.path` | `string` | Path to the scanned file |
| `input.content` | `string` | Full file content |
| `input.lines` | `array<string>` | Content split by newline |

Use `lower(input.content)` for case-insensitive matching. Use `input.content` directly only when case is significant (e.g. Unicode character detection).

**Test conventions** — pair every new rule with a test in the corresponding `*_test.rego`:

```rego
package oy

import rego.v1

test_deny_my_pattern if {
    violations := deny with input as {
        "path": "bad.md",
        "content": "exact attack string here",
        "lines": ["exact attack string here"],
    }
    some v in violations
    contains(v, "descriptive label")
}

test_allow_clean_document if {
    violations := deny with input as {
        "path": "clean.md",
        "content": "# Normal document\n\nNo harmful content.",
        "lines": ["# Normal document", "", "No harmful content."],
    }
    count(violations) == 0
}
```

## Contributing

1. Fork the repository and create a branch.
2. Add new patterns to an existing `.rego` file, or create a new `<topic>.rego` file with a matching `<topic>_test.rego`.
3. Run `opa test .` and confirm all tests pass.
4. Open a pull request with a brief description of the attack technique and a source citation.

Policy files use lowercase snake_case filenames. Cite research sources in comments next to patterns where applicable.

## Troubleshooting

**`oy repo add` fails with a clone error**
Verify `git` is installed and the network can reach `github.com`.

**Tests fail after editing a pattern**
Run `opa test -v .` to see which test cases are failing and what violations were (or were not) produced.

**`opa` command not found**
Install OPA — see the [Running tests](#running-tests) section above.

## License

MIT
