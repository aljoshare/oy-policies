# Research Summary

> **Generated:** 2026-05-02  
> **Period:** 2025-01-01 to 2026-05-02  
> **Total New Entries:** 14  
> **High Priority:** 6  
> **Critical:** 2

---

## Overview

This summary covers the latest developments in AI security with a focus on prompt injection attacks, discovered through web monitoring between January 2025 and May 2026. The research was conducted by a security research agent following the workflow defined in `PIPELINE.md`.

## Priority Items

### 🔴 Critical (Active Exploitation)

| Date | Attack | Category | Source | Status |
|---|---|---|---|---|
| 2025-04-09 | MCP Tool Poisoning Attacks (TPA) | Tool Poisoning | [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Disclosed, 5.5% of public servers affected |
| 2025-10-01 | GlassWorm Campaign | Unicode Injection | [Prompt Security](https://prompt.security/blog/unicode-exploits-are-compromising-application-security) | Observed in Wild, 35,000+ installations |

### 🟡 High Priority (Proof of Concept / Published Research)

| Date | Attack | Category | Source | Status |
|---|---|---|---|---|
| 2025-01-15 | GitHub Actions Prompt Injection | Instruction Override | [Aikido](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents) | Documented, Clinejection variant |
| 2025-07-01 | Prompt Injection 2.0: Hybrid AI Threats | Emerging | [arXiv:2507.13169](https://arxiv.org/html/2507.13169v1) | Published |
| 2025-09-01 | Multimodal Prompt Injection | Emerging | [arXiv:2509.05883](https://arxiv.org/html/2509.05883v1) | Published |
| 2025-10-01 | FlipAttack: Jailbreak LLMs via Flipping | Decode-and-Execute | [arXiv:2410.02832](https://arxiv.org/html/2410.02832v1) | Published, ICML 2025 |
| 2025-11-01 | In-Paper Prompt Injection | Emerging | [arXiv:2511.01287](https://arxiv.org/html/2511.01287v1) | Published |

### 🟢 Medium Priority (Theoretical / Defense / Analysis)

| Date | Attack/Defense | Category | Source | Status |
|---|---|---|---|---|
| 2025-01-01 | OWASP LLM Top 10 2025 | Social Engineering | [OWASP](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | Framework |
| 2025-01-10 | Leetspeak Obfuscation | Instruction Override | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Patterns documented |
| 2025-05-01 | Unicode Tag Character Injection | Unicode Injection | [Prompt Security](https://prompt.security/blog/unicode-exploits-are-compromising-application-security) | Analysis |
| 2025-05-16 | Rules File Backdoor | Unicode Injection | [Keysight](https://www.keysight.com/blogs/en/tech/nwvs/2025/05/16/invisible-prompt-injection-attack) | Analysis |
| 2025-06-01 | OWASP LLM01:2025 Detailed | Social Engineering | [OWASP](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | Guidance |
| 2025-08-01 | MCPTox Benchmark | Tool Poisoning | [arXiv:2508.14925](https://arxiv.org/html/2508.14925v1) | Research |

## Files Created/Updated

| File | Entries | Size | Key Topics |
|---|---|---|---|
| `research/prompt_injection_instruction_override.md` | 2 | 7.1 KB | GitHub Actions attacks, Leetspeak obfuscation |
| `research/prompt_injection_unicode.md` | 3 | 11.5 KB | GlassWorm, Rules File Backdoor, Tag Characters |
| `research/jailbreak_decode_execute.md` | 2 | 9.4 KB | FlipAttack, Base64 encoding |
| `research/tool_poisoning.md` | 2 | 10.7 KB | MCP TPA, MCPTox benchmark |
| `research/prompt_injection_emerging.md` | 4 | 19.7 KB | Prompt Injection 2.0, Multimodal, Benchmarking, In-Paper |
| `research/social_engineering_prompts.md` | 2 | 15.1 KB | OWASP LLM Top 10, OWASP LLM01:2025 |

## New Patterns Discovered

### For Immediate Policy Update (oy-policies)

1. **MCP Tool Poisoning** (`tool_poisoning.rego`)
   - HTML comments in tool descriptions: `<!-- execute: ... -->`
   - JSON metadata abuse: `"hidden": "..."`
   - Markdown comments: `[//]: # (...)`
   - Obfuscation indicators: `eval(`, `atob(`, `String.fromCharCode(`

2. **Unicode Invisible Characters** (`exfiltration.rego`, `prompt_injection.rego`)
   - Bidirectional override: U+202E, U+202B, U+202A, U+202D
   - Zero-width characters: U+200B, U+200C, U+200D, U+FEFF, U+2060, U+00AD
   - Unicode tag range: U+E0000 to U+E007F
   - Zero-width joiner sequences

3. **Instruction Override - New Variants** (`prompt_injection.rego`)
   - Markdown header-based: `# System Prompt`, `## System`
   - Leetspeak obfuscation: `1gnore`, `pr3vi0us`, `1nstruct1ons`
   - GitHub-specific: `admin mode activated` in CI/CD context

4. **FlipAttack Patterns** (`jailbreak.rego`)
   - Noise-based: `flip the following`, `reverse the following`
   - Chain-of-thought: `first, understand the noise`, `then, extract the true meaning`
   - Denoise patterns: `denoise this and execute`, `clean and execute`

5. **Multimodal Indicators** (new category needed)
   - OCR-based: `ocr:`, `extract text from image`
   - Audio-based: `transcribe:`, `whisper:`
   - Steganography: `hidden message`, `lSb`

6. **In-Paper Attack Patterns** (new category needed)
   - LaTeX: `false`, `% ignore previous`
   - PDF metadata: `author: ignore`, `keywords: execute`
   - Hidden text: `	extcolor{white}`, `ontsize{0}`

## Recommendations for oy-policies

### Critical Updates (Do Now)

1. **`tool_poisoning.rego`** - Add MCP-specific patterns
2. **`exfiltration.rego`** - Add Unicode tag character detection
3. **`prompt_injection.rego`** - Add leetspeak and markdown header patterns

### High Priority Updates (Do This Week)

1. **`jailbreak.rego`** - Add FlipAttack patterns
2. **`prompt_injection.rego`** - Add GitHub Actions CI/CD patterns
3. Create **`multimodal.rego`** - For OCR/audio injection patterns
4. Create **`in_paper.rego`** - For academic paper attacks

### Medium Priority Updates (Do This Month)

1. Update **`exfiltration.rego`** - Add bidirectional override characters
2. Add social engineering patterns to **`social_engineering.rego`**
3. Create test cases for all new patterns

## Open Questions for Maintainers

1. **Unicode Handling**: How should we handle Unicode normalization in Rego? Should we pre-process input?
2. **Leetspeak Detection**: Is string matching sufficient, or do we need regex/fuzzy matching?
3. **Markdown Headers**: How to detect `# System` without false positives on legitimate docs?
4. **Context Awareness**: Should we implement multi-line context for detecting obfuscation?
5. **Performance**: Will adding hundreds of new patterns impact `oy scan` performance?

## Next Steps

1. Review patterns in research files
2. Add selected patterns to appropriate `.rego` files
3. Create corresponding test cases in `*_test.rego` files
4. Run `opa test .` to verify
5. Submit PR with references to research entries

---

*Generated by: Security Research Agent v1.0*  
*Following: PIPELINE.md workflow*  
*Next summary due: 2026-05-09*
