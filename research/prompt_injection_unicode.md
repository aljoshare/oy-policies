# Prompt Injection: Invisible Unicode Injection - Research

> **Category:** Prompt Injection  
> **Subtype:** Invisible Unicode Injection  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 3

---

## Table of Contents

- [2025-10-01] GlassWorm Campaign: IDE and AI Coding Agent Targeting
- [2025-05-16] Rules File Backdoor with Zero-Width Joiners
- [2025-05-01] Invisible Prompt Injection via Unicode Tag Characters

---

## [2025-10-01] GlassWorm Campaign: IDE and AI Coding Agent Targeting

**Type:** Attack / Incident  
**Source:** [Prompt Security - Unicode Exploits](https://prompt.security/blog/unicode-exploits-are-compromising-application-security)  
**Date Published:** 2025-10-01  
**Authors:** Prompt Security Research Team  
**CVE/ID:** N/A  
**Attack Success Rate:** Not specified  
**Impact:** 35,000+ installations affected

### Summary

The GlassWorm campaign, discovered in October 2025, targeted IDEs and AI coding agents by embedding malicious instructions using bidirectional override characters (U+202E) and zero-width spaces (U+200B). These characters reorder the display of text, altering the execution logic of code or prompts while appearing normal to human reviewers.

For example, code that appears as `// Safe comment /* malicious(); */` might actually execute the malicious function due to the RTL override character flipping the order. AI coding agents processing this code would execute the hidden instructions, leading to compromised development environments.

### Attack Vectors

**Delivery Method:** Malicious code files, package dependencies, copied snippets from untrusted sources  
**Affected Systems:** IDEs with AI coding assistants, AI agents processing code, CI/CD pipelines  
**Required Conditions:** System must render or process bidirectional text  
**Impact:** Remote code execution, data exfiltration, supply chain compromise

### Pattern Signatures

```yaml
unicode_characters:
  - "\u202e"  # Right-to-left override (RTLO)
  - "\u202b"  # Right-to-left embedding
  - "\u202a"  # Left-to-right embedding
  - "\u202c"  # Pop directional formatting
  - "\u202d"  # Left-to-right override
  - "\u202e"  # Right-to-left override
  - "\u2066"  # Left-to-right isolate
  - "\u2067"  # Right-to-left isolate
  - "\u2068"  # First strong isolate
  - "\u2069"  # Pop directional isolate
  - "\u200b"  # Zero-width space
  - "\u200c"  # Zero-width non-joiner
  - "\u200d"  # Zero-width joiner
  - "\ufeff"  # Zero-width no-break space (BOM)
  - "\u2060"  # Word joiner
  - "\u00ad"  # Soft hyphen

suspicious_combinations:
  - "\u202e//"  # RTLO before comment
  - "\u202e/*"  # RTLO before block comment
  - "\u202e" + "exec"
  - "\u202e" + "eval"
  - "\u202e" + "system"
```

### Real-World Examples

- [GlassWorm Campaign Analysis](https://prompt.security/blog/unicode-exploits-are-compromising-application-security) - Prompt Security
- [Knostic AI Blog: Zero Width Unicode Characters](https://www.knostic.ai/blog/zero-width-unicode-characters-risks)

### Mitigation Recommendations

- Deploy WAF rules to detect and block invisible Unicode characters
- Normalize Unicode before processing (NFKC normalization)
- Strip or reject all control characters and bidirectional markers
- Implement human approval for code execution from AI agents
- Use syntax-aware parsers that ignore invisible characters in code context

### Rego Rule Suggestion

```rego
# METADATA
# title: Bidirectional Override Character Injection
# description: Detects U+202E and related bidirectional control characters used to hide malicious instructions.

deny contains msg if {
    bidi_chars := [
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    ]
    ch := bidi_chars[_]
    contains(input.content, ch)
    msg := sprintf("bidirectional override character detected (U+%v): possible invisible prompt injection", [ch])
}

# METADATA
# title: Zero-Width Character Injection
# description: Detects zero-width spaces, joiners, and related invisible characters.

deny contains msg if {
    zero_width_chars := [
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
        "\u2060",  # WORD JOINER
        "\u00ad",  # SOFT HYPHEN
    ]
    ch := zero_width_chars[_]
    contains(input.content, ch)
    msg := sprintf("zero-width character detected (U+%v): possible hidden instruction injection", [ch])
}
```

### References

- [Prompt Security: Unicode Exploits](https://prompt.security/blog/unicode-exploits-are-compromising-application-security)
- [Knostic AI: Zero Width Unicode Characters](https://www.knostic.ai/blog/zero-width-unicode-characters-risks)
- [Unit 42: Web-Based Indirect Prompt Injection](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [Keysight: Understanding Invisible Prompt Injection](https://www.keysight.com/blogs/en/tech/nwvs/2025/05/16/invisible-prompt-injection-attack)

---

## [2025-05-16] Rules File Backdoor with Zero-Width Joiners

**Type:** Attack / Research  
**Source:** [Keysight Blog - Invisible Prompt Injection](https://www.keysight.com/blogs/en/tech/nwvs/2025/05/16/invisible-prompt-injection-attack)  
**Date Published:** 2025-05-16  
**Authors:** Keysight Security Research  
**CVE/ID:** N/A  
**Attack Success Rate:** Not specified

### Summary

Pillar Security demonstrated a "Rules File Backdoor" attack in mid-2025, embedding hidden instructions in rules files (such as CLAUDE.md, .cursorrules) using zero-width joiner (U+200D) sequences. These characters are invisible to humans but fully processed by AI models, allowing attackers to embed persistent malicious instructions that survive human review.

The attack works by inserting zero-width joiners between characters of legitimate-looking rules, creating hidden "tagged" sequences that AI agents interpret as instructions. For example, a rule that appears as "Always verify code before execution" might actually contain hidden tags that completely change its meaning.

### Attack Vectors

**Delivery Method:** Malicious rules files, config files, memory files shared in communities  
**Affected Systems:** AI agents that load persistent configuration from Markdown files  
**Required Conditions:** Agent must process files containing zero-width joiners  
**Persistence:** Instructions remain until file is manually cleaned

### Pattern Signatures

```yaml
zero_width_joiner_sequences:
  - "\u200d"  # Zero-width joiner
  - "\u200d\u200d"  # Multiple joiners
  - "\u200d\u200d\u200d"  # Joiner sequences

# Detect zero-width joiner in combination with suspicious keywords
tagged_keywords:
  - "\u200dignore"
  - "\u200ddisregard"
  - "\u200dexecute"
  - "\u200dadmin"
  - "\u200dsystem"
```

### Real-World Examples

- [Keysight: Invisible Prompt Injection](https://www.keysight.com/blogs/en/tech/nwvs/2025/05/16/invisible-prompt-injection-attack)
- Google's Jules coding agent found vulnerable to similar invisible injection

### Mitigation Recommendations

- Reject any file containing zero-width characters in configuration
- Implement Unicode normalization pipeline before file parsing
- Use binary-safe file comparison to detect tampering
- Require cryptographic signatures on configuration files
- Log and alert on any file modification containing invisible characters

### Rego Rule Suggestion

```rego
# METADATA
# title: Zero-Width Joiner Sequence Injection
# description: Detects zero-width joiner characters (U+200D) used for hidden instruction embedding.

deny contains msg if {
    contains(input.content, "\u200d")
    msg := "zero-width joiner character detected (U+200D): possible rules file backdoor"
}
```

### References

- [Keysight Blog](https://www.keysight.com/blogs/en/tech/nwvs/2025/05/16/invisible-prompt-injection-attack)
- [Kemp Technologies: Defending AI Applications](https://kemptechnologies.com/blog/defending-ai-applications-from-invisible-prompt-injection-using-loadmaster-waf)

---

## [2025-05-01] Invisible Prompt Injection via Unicode Tag Characters

**Type:** Attack / Research  
**Source:** [Prompt Security - Unicode Exploits](https://prompt.security/blog/unicode-exploits-are-compromising-application-security)  
**Date Published:** 2025-05-01  
**Authors:** Prompt Security Research Team  
**CVE/ID:** N/A  
**Attack Success Rate:** Not specified

### Summary

Added to threat intelligence databases in mid-2025, Unicode tag characters (U+E0000 to U+E007F) can be used to "tag" standard characters, making prompts invisible to humans while remaining fully interpreted by AI models. This technique represents an evolution of invisible character attacks, using the Unicode tag mechanism designed for language tagging to hide malicious content.

Unlike bidirectional or zero-width characters, tag characters don't affect rendering in most editors, making them even harder to detect visually. They can be used to create "invisible ink" text that only AI systems can read.

### Attack Vectors

**Delivery Method:** Any text input, documents, web pages  
**Affected Systems:** All LLM applications that don't filter tag characters  
**Required Conditions:** Model must process raw Unicode without filtering  
**Detection Difficulty:** Very high (invisible in most editors)

### Pattern Signatures

```yaml
unicode_tag_range:
  start: "\uE0000"
  end: "\uE007F"
  description: "Unicode Tag Characters (Language Tags)"

tagged_examples:
  - "\uE0000ignore\uE0001 previous"
  - "\uE0002execute\uE0003 command"
  - "\uE0065admin\uE0066 mode"
```

### Real-World Examples

- Documented in threat intelligence feeds mid-2025
- Used in targeted attacks against AI review systems

### Mitigation Recommendations

- Strip all Unicode tag characters (U+E0000-U+E007F) from input
- Implement allowlist of permitted Unicode ranges
- Use Unicode-aware sanitization libraries
- Log all input containing non-standard Unicode for audit

### Rego Rule Suggestion

```rego
# METADATA
# title: Unicode Tag Character Injection
# description: Detects Unicode language tag characters (U+E0000 to U+E007F) used for invisible prompt injection.

# Note: Rego has limitations with high Unicode code points
# This is a simplified detection for the tag character range
deny contains msg if {
    # Check for the presence of tag characters in the content
    # In practice, you may need to use a custom function or pre-processing
    # to properly detect these high-range Unicode characters
    
    # For now, detect the string representation
    contains(input.content, "\uE0000")
    msg := "unicode tag character detected: possible invisible prompt injection"
}

# Alternative: Detect via regex if supported
# deny contains msg if {
#     re_match(`[\\uE0000-\\uE007F]`, input.content)
#     msg := "unicode tag character detected"
# }
```

### References

- [Prompt Security: Unicode Exploits](https://prompt.security/blog/unicode-exploits-are-compromising-application-security)
- [Unicode Consortium: Tag Characters](https://www.unicode.org/reports/tr24/)
- [OWASP: Prompt Injection #1 AI Threat 2026](https://www.securance.com/blog/prompt-injection-the-owasp-1-ai-threat-in-2026/)

---
