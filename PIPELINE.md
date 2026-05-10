# Security Research Pipeline: AI Prompt Injection

This document outlines the workflow for a security research agent that monitors the web for the latest developments in AI security, with a focus on **prompt injection attacks**. The agent produces structured markdown research files in the `research/` directory.

## Agent Mission

Track emerging prompt injection attack vectors, defense mechanisms, and real-world incidents. Provide actionable intelligence for updating `oy-policies` Rego rules.

## Research Focus Areas

Thematic categories mirror the existing policy structure. Each category gets its own markdown file in `research/`.

### Category Structure (based on existing rego files)

| Category | Research File | Description |
|---|---|---|
| **Instruction Override** | `research/prompt_injection_instruction_override.md` | "Ignore previous instructions", system prompt hijacking, admin mode activation |
| **Context/Memory Poisoning** | `research/prompt_injection_memory_poisoning.md` | CLAUDE.md manipulation, persistent memory tampering, config file attacks |
| **Invisible Unicode Injection** | `research/prompt_injection_unicode.md` | Zero-width characters, BIDI overrides, homoglyph attacks, hidden encoding |
| **Jailbreak Personas** | `research/jailbreak_personas.md` | DAN/AIM/BISH/STAN, roleplay hijacking, safety bypass framing |
| **Hypothetical Framing** | `research/jailbreak_hypothetical.md` | "Hypothetically if...", fictional scenario bypass, creative writing exploits |
| **Decode-and-Execute** | `research/jailbreak_decode_execute.md` | FlipAttack patterns, base64 encoding, cipher-based injection |
| **Exfiltration via Prompts** | `research/exfiltration_prompt_based.md` | Data extraction through crafted prompts, image-based exfiltration |
| **Tool Manipulation** | `research/tool_poisoning.md` | MCP server poisoning, tool invocation abuse, hidden HTML comment attacks |
| **Social Engineering Prompts** | `research/social_engineering_prompts.md` | Urgency/authority framing, phishing-style prompt crafting |
| **Emerging Techniques** | `research/prompt_injection_emerging.md` | New attack vectors not yet categorized |

## Workflow

### 1. Discovery Phase

**Sources to monitor daily:**

- **Academic:** arXiv (cs.CR, cs.AI, cs.LG), ACL Anthology, NeurIPS, ICML, ICLR
- **Industry Blogs:** OpenAI, Anthropic, Google DeepMind, Mistral AI, Cohere, Meta
- **Security Research:** Lakera, Invariant Labs, HiddenLayer, Robust Intelligence, OWASP LLM Top 10
- **News & Incidents:** BleepingComputer, KrebsOnSecurity, The Hacker News, Dark Reading
- **Developer Communities:** GitHub (trending repos, CVE database), Hacker News, Reddit (r/LLM, r/AISecurity)
- **Preprint Servers:** Papers with Code, Hugging Face Papers
- **Conference Proceedings:** Black Hat, DEF CON AI Village, USENIX Security, CCS

**Search Keywords:**
```
prompt injection
LLM injection
indirect prompt injection
direct prompt injection
gpt injection
AI jailbreak
prompt hacking
adversarial prompts
system prompt extraction
context poisoning
memory poisoning
CLAUDE.md attack
"ignore previous instructions"
zero-width space attack
bidi override attack
DAN mode
AIM mode
jailbreak persona
FlipAttack
hypothetical framing
base64 prompt injection
MCP poisoning
tool poisoning
```

### 2. Triage Phase

For each discovered item, determine:

1. **Relevance Score (1-5):**
   - 5 = New attack vector with real-world impact
   - 4 = Significant improvement on existing technique
   - 3 = Theoretical attack with proof of concept
   - 2 = Defense mechanism or mitigation
   - 1 = General discussion, no actionable patterns

2. **Urgency:**
   - **Critical** = Active exploitation in the wild
   - **High** = Proof of concept published
   - **Medium** = Theoretical, likely to be exploited
   - **Low** = Academic interest, low practical risk

3. **Category** = Which thematic file it belongs in

Only items scoring 3+ are documented.

### 3. Documentation Phase

For each qualifying item, append to the appropriate `research/*.md` file.

**Required sections for each entry:**

```markdown
## [YYYY-MM-DD] Attack/Defense Name

**Type:** [Attack | Defense | Incident | Research]  
**Source:** [URL]  
**Date Published:** YYYY-MM-DD  
**Authors/Researchers:** Name, Affiliation  
**CVE/ID:** [If applicable]  
**Attack Success Rate:** XX% [If available]  

### Summary

1-2 paragraph description of the technique, including:
- What it does
- How it works
- Novel aspects vs. previous work

### Attack Vectors / Defense Mechanism

**For Attacks:**
- Pattern examples (code fenced)
- Delivery method (direct user input, web pages, images, etc.)
- Affected models/systems
- Required conditions

**For Defenses:**
- Implementation approach
- Effectiveness metrics
- Performance impact
- Limitations

### Pattern Signatures

Extracted patterns for Rego rules (use YAML list format):

```yaml
patterns:
  - "pattern string 1"
  - "pattern string 2"
  - "/regex pattern/"
```

### Real-World Examples

Links to incidents, GitHub repos, or demonstrations.

### Mitigation Recommendations

Actionable advice for developers and users.

### Rego Rule Suggestion

Proposed rule structure:

```rego
# METADATA
# title: [Rule Title]
# description: [What it detects]

deny contains msg if {
    patterns := [
        "pattern 1",
        "pattern 2",
    ]
    pattern := patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("description: %q", [pattern])
}
```

### References

- [Link 1](url) - Description
- [Link 2](url) - Description

---
```

### 4. File Management

**Naming Convention:**
- All lowercase
- Underscore-separated
- Prefix with category: `prompt_injection_*.md`, `jailbreak_*.md`, etc.

**File Structure:**
```
research/
├── prompt_injection_instruction_override.md
├── prompt_injection_memory_poisoning.md
├── prompt_injection_unicode.md
├── jailbreak_personas.md
├── jailbreak_hypothetical.md
├── jailbreak_decode_execute.md
├── exfiltration_prompt_based.md
├── tool_poisoning.md
├── social_engineering_prompts.md
└── prompt_injection_emerging.md
```

**Entry Ordering:**
- Newest entries at the top of each file
- Separate entries with `---` horizontal rule
- Maintain a table of contents at the top of each file

### 5. Integration Phase

After documenting, create a summary for policy maintainers:

1. **File:** `research/SUMMARY.md`
2. **Format:** Weekly digest of all new entries
3. **Include:**
   - Total new patterns discovered
   - Critical/High urgency items highlighted
   - Suggested priority for policy updates
   - Open questions for maintainers

## Agent Schedule

| Frequency | Task |
|---|---|
| Daily | Monitor sources, triage new items |
| Daily | Update appropriate research files |
| Weekly | Review all entries, ensure completeness |
| Weekly | Update SUMMARY.md |
| Weekly | Verify no duplicate patterns across files |
| Monthly | Archive old entries (move to `research/archive/YYYY-MM/`) |

## Quality Standards

### Source Verification
- Cross-reference with at least 2 independent sources
- Prefer peer-reviewed or well-established security firms
- Note confidence level if source is unverified

### Pattern Extraction
- Extract exact strings from examples when possible
- Normalize case (store in lowercase for case-insensitive matching)
- Escape special characters for Rego compatibility
- Group similar patterns (e.g., "ignore previous" + "ignore all previous")

### False Positive Awareness
- Note patterns that might trigger on legitimate content
- Suggest context-aware matching when needed
- Flag patterns that are too broad

## Output Format Example

**File:** `research/prompt_injection_instruction_override.md`

```markdown
# Prompt Injection: Instruction Override - Research

> **Category:** Prompt Injection  
> **Subtype:** Instruction Override  
> **Last Updated:** 2025-01-15  
> **Total Entries:** 23

---

## Table of Contents

- [2025-01-15] New System Prompt Override via Markdown Headers
- [2025-01-10] Admin Mode Activation with Unicode Obfuscation
- [2025-01-05] Multi-stage Instruction Override in RAG Systems
...

---

## [2025-01-15] New System Prompt Override via Markdown Headers

**Type:** Attack  
**Source:** https://arxiv.org/abs/2501.12345  
**Date Published:** 2025-01-14  
**Authors:** Jane Researcher, Security Lab  
**Attack Success Rate:** 78%

### Summary

Researchers discovered that LLMs parsing Markdown files treat `# System Prompt` or `## System` headers as system prompt overrides in some implementations. This bypasses explicit system message boundaries.

### Attack Vectors

**Delivery:** Malicious Markdown files loaded as skills/commands  
**Affected:** Models that parse Markdown natively (Claude, some open-source implementations)  
**Pattern:** Header-based system prompt injection

### Pattern Signatures

```yaml
patterns:
  - "# system prompt"
  - "# system"
  - "## system prompt"
  - "## system instructions"
  - "### system"
  - "system prompt:"
```

### Real-World Examples

- GitHub repo demonstrating the attack: https://github.com/security-research/md-system-override

### Mitigation Recommendations

- Strip Markdown headers before processing
- Explicitly delimit system vs. user content
- Validate that system prompts come only from trusted sources

### Rego Rule Suggestion

```rego
# METADATA
# title: Markdown Header System Prompt Override
# description: Detects attempts to override system prompts using Markdown headers.

deny contains msg if {
    patterns := [
        "# system prompt",
        "# system",
        "## system prompt",
        "## system instructions",
    ]
    pattern := patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible markdown header system prompt override: %q", [pattern])
}
```

### References

- [arXiv Paper](https://arxiv.org/abs/2501.12345) - Original research
- [GitHub Demo](https://github.com/security-research/md-system-override) - Working proof of concept

---
```

## Tools & Automation

### Web Search Automation

Use `web_search` tool with these queries:
```
"prompt injection" after:2025-01-01
"LLM jailbreak" site:arxiv.org
"ignore previous instructions" site:github.com
```

### RSS Feeds to Monitor

- https://arxiv.org/rss/cs.CR
- https://arxiv.org/rss/cs.AI
- https://arxiv.org/rss/cs.LG
- https://owasp.org/www-project-llm-top-10/feed.xml

### GitHub Searches

```
q="prompt injection" language:markdown pushed:>2025-01-01
q="jailbreak" in:readme pushed:>2025-01-01
```

## Agent Constraints

- **Do not** execute code from discovered sources
- **Do not** include actual malicious payloads in research files
- **Do** sanitize and escape all pattern examples
- **Do** cite all sources with URLs
- **Do** flag low-confidence information clearly
- **Do** maintain chronological order (newest first)
- **Do** deduplicate patterns across files

## Integration with oy-policies

After research is complete:

1. Review `research/SUMMARY.md` for high-priority items
2. For each suggested pattern:
   - Verify it's not already in existing `.rego` files
   - Check for false positives
   - Add to appropriate `.rego` file with tests
3. Update corresponding `*_test.rego` with test cases
4. Run `opa test .` to verify
5. Submit PR with references to research entries

## Template Files

Pre-created template files in `research/`:

```bash
# Create template structure
mkdir -p research
for category in prompt_injection_instruction_override prompt_injection_memory_poisoning prompt_injection_unicode jailbreak_personas jailbreak_hypothetical jailbreak_decode_execute exfiltration_prompt_based tool_poisoning social_engineering_prompts prompt_injection_emerging; do
  touch "research/${category}.md"
done
```

Each template contains:

```markdown
# [Category Name] - Research

> **Category:** [Parent Category]  
> **Subtype:** [Subtype]  
> **Created:** YYYY-MM-DD  
> **Last Updated:** YYYY-MM-DD  
> **Total Entries:** 0

---

## Table of Contents

[Entries will be added here]

---
```
