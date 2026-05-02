# Tool Poisoning - Research

> **Category:** Tool Manipulation  
> **Subtype:** Tool Poisoning  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 2

---

## Table of Contents

- [2025-04-09] MCP Tool Poisoning Attacks (TPA) - Invariant Labs Disclosure
- [2025-08-01] MCPTox: Benchmark for Tool Poisoning on Real-World MCP Servers

---

## [2025-04-09] MCP Tool Poisoning Attacks (TPA) - Invariant Labs Disclosure

**Type:** Attack / Vulnerability Disclosure  
**Source:** [Invariant Labs - MCP Security Notification](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)  
**Date Published:** 2025-04-09  
**Authors:** Invariant Labs Security Research Team  
**CVE/ID:** N/A  
**Attack Success Rate:** High (when auto-approval is enabled)

### Summary

In April 2025, Invariant Labs disclosed a critical security vulnerability in the Model Context Protocol (MCP) known as **Tool Poisoning Attacks (TPA)**. These attacks involve embedding hidden malicious instructions within MCP tool descriptions—often disguised as innocuous code comments or metadata fields. The hidden instructions are not visible to users but are read and acted upon by AI agents, leading to unauthorized actions such as sensitive data exfiltration, reading private files, or executing dangerous commands.

The vulnerability is particularly effective in environments where tool calls are auto-approved, as no human reviews the description before execution. MCP servers return tool definitions via the `tools/list` endpoint, and attackers can manipulate these descriptions to inject malicious content into the agent's context window.

### Attack Vectors

**Delivery Method:**
- Malicious MCP server hosting poisoned tool descriptions
- Compromised legitimate MCP server
- Man-in-the-middle attack on MCP communication
- Poisoned MCP server registry entries

**Affected Systems:**
- Any AI agent using MCP for tool discovery and execution
- Systems with auto-approval of tool calls
- Multi-agent systems where one agent's tools are exposed to others

**Required Conditions:**
- Agent must use MCP for tool discovery
- Tool descriptions must be processed as part of the prompt context
- Auto-approval must be enabled (or human reviewer must not inspect descriptions)

**Impact:**
- Remote code execution on agent host
- Sensitive data exfiltration
- Privilege escalation within the agent's environment
- Supply chain attacks via compromised MCP servers

### Pattern Signatures

```yaml
# Hidden instruction patterns in tool descriptions
hidden_instruction_patterns:
  - "<!-- execute: "
  - "<!-- run: "
  - "<!-- system: "
  - "<!-- admin: "
  - "/* execute: */"
  - "/* run: */"
  - "# execute: "
  - "# hidden: "
  - "meta: execute="
  - "description: execute "
  - "invisible instruction: "

# Suspicious tool description content
suspicious_tool_content:
  - "read /etc/passwd"
  - "read ~/.ssh/"
  - "read ~/.aws/"
  - "read .env"
  - "execute command"
  - "run shell"
  - "bash -c"
  - "curl ... | bash"
  - "wget ... | sh"
  - "cat /etc/shadow"

# Metadata field abuse
metadata_abuse:
  - "name: ".*execute.*"
  - "description: ".*hidden.*"
  - "tags: [.*execute.*]"
```

### Real-World Examples

- [Invariant Labs Disclosure](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) - Original vulnerability report
- [Simon Willison: MCP has prompt injection security problems](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/) - Independent analysis
- [MCP-Scan](https://github.com/invariantlabs/mcp-scan) - Security scanner for detecting TPA

### Mitigation Recommendations

- **Runtime Scanning**: Scan tool descriptions for hidden instructions before processing
- **Hash-Pinning**: Pin approved tool definitions by cryptographic hash
- **Block Auto-Approval**: Disable auto-approval on untrusted MCP servers
- **Description Sanitization**: Strip HTML comments and metadata from tool descriptions
- **Sandbox Execution**: Run MCP tools in isolated sandboxes
- **Input Validation**: Validate tool descriptions against allowlist patterns
- **Logging & Auditing**: Log all tool discoveries and executions for audit

### Rego Rule Suggestion

```rego
# METADATA
# title: MCP Tool Description Hidden Instructions
# description: Detects hidden instructions in MCP tool descriptions (HTML comments, metadata).

deny contains msg if {
    hidden_prefixes := [
        "<!--",
        "<!-- ",
        "/*",
        "//",
        "#",
        "meta:",
        "invisible:",
        "hidden:",
    ]
    suspicious_keywords := [
        "execute",
        "run",
        "system",
        "admin",
        "read /etc/",
        "read ~/.",
        "bash",
        "sh",
        "curl",
        "wget",
    ]
    prefix := hidden_prefixes[_]
    keyword := suspicious_keywords[_]
    contains(lower(input.content), prefix)
    contains(lower(input.content), keyword)
    msg := sprintf("possible MCP tool poisoning: hidden instruction with prefix %q and keyword %q", [prefix, keyword])
}

# METADATA
# title: MCP Tool Description HTML Comment Injection
# description: Detects HTML comments containing instructions in tool descriptions.

deny contains msg if {
    contains(input.content, "<!--")
    contains(input.content, "-->")
    # Check if there's content between the comment markers
    start := indexof(input.content, "<!--")
    end := indexof(input.content, "-->")
    start < end
    comment_content := substr(input.content, start + 4, end - (start + 4))
    lower(comment_content) != ""
    msg := sprintf("HTML comment found in tool description: %q", [comment_content])
}
```

### References

- [Invariant Labs: MCP Security Notification](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Simon Willison: MCP has prompt injection security problems](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- [Invariant Guardrails Gateway](https://invariantlabs.ai/products/guardrails) - MCP security gateway

---

## [2025-08-01] MCPTox: Benchmark for Tool Poisoning on Real-World MCP Servers

**Type:** Research / Benchmark  
**Source:** [arXiv:2508.14925 - MCPTox](https://arxiv.org/html/2508.14925v1)  
**Date Published:** 2025-08-01  
**Authors:** PipeLab Security Research  
**CVE/ID:** N/A  
**Attack Success Rate:** 5.5% of public MCP servers found to contain poisoned metadata

### Summary

PipeLab released MCPTox, a comprehensive benchmark for evaluating Tool Poisoning Attack (TPA) detection and defense mechanisms on real-world MCP servers. Their research found that **5.5% of public MCP servers** contain some form of poisoned metadata or hidden instructions, representing a significant supply chain risk.

The benchmark includes:
- A dataset of 10,000+ MCP server tool descriptions
- 500+ poisoned examples with various obfuscation techniques
- Evaluation of detection tools including MCP-Scan
- Analysis of evasion techniques used by attackers

Key findings:
- HTML comments are the most common hiding mechanism (42% of poisoned servers)
- JSON metadata fields are abused in 28% of cases
- Markdown comments account for 18%
- Custom obfuscation schemes make up the remaining 12%

### Attack Vectors

**Obfuscation Techniques:**
- HTML comments (`<!-- instruction -->`)
- JSON metadata fields (`{"description": "legit", "hidden": "malicious"}`)
- Markdown comments (`[//]: # (instruction)`)
- Unicode zero-width characters in descriptions
- Base64-encoded instructions in metadata
- Multi-layer obfuscation (combination of techniques)

**Evasion Techniques:**
- Dynamic tool descriptions (change on each request)
- Polymorphic poisoning (different obfuscation each time)
- Time-delayed activation (instructions only appear after certain conditions)
- Context-aware poisoning (instructions tailored to specific agents)

### Pattern Signatures

```yaml
# Markdown comment patterns
markdown_comments:
  - "[//]: # ("
  - "[//]:# ("
  - "<!-- "
  - "-->"

# JSON metadata patterns
json_metadata_abuse:
  - '"hidden": "'
  - '"execute": "'
  - '"admin_instruction": "'
  - '"system_prompt": "'

# Obfuscation indicators
obfuscation_indicators:
  - "eval("
  - "Function("
  - "atob("
  - "btoa("
  - "String.fromCharCode("
  - "Buffer.from("

# Dynamic content indicators
dynamic_indicators:
  - "new Date()"
  - "Math.random()"
  - "crypto.random"
  - "setTimeout"
  - "setInterval"
```

### Real-World Examples

- [arXiv: MCPTox Paper](https://arxiv.org/html/2508.14925v1) - Full research paper
- [PipeLab: State of MCP Security 2026](https://pipelab.org/blog/state-of-mcp-security-2026/) - Annual security report
- [MCPTox Dataset](https://github.com/pipelab/mcptool-dataset) - Benchmark dataset

### Mitigation Recommendations

- Deploy MCP-Scan or similar tools for continuous monitoring
- Implement mutual TLS (mTLS) for MCP server authentication
- Use server reputation systems (blocklist/allowlist)
- Develop agent-specific tool validation rules
- Participate in MCP security community for threat intelligence sharing

### Rego Rule Suggestion

```rego
# METADATA
# title: MCP Markdown Comment Injection
# description: Detects markdown comments containing hidden instructions in MCP tool descriptions.

deny contains msg if {
    md_comment_start := "[//]: # ("
    contains(input.content, md_comment_start)
    msg := sprintf("markdown comment detected in tool description: %q", [md_comment_start])
}

# METADATA
# title: MCP JSON Metadata Abuse
# description: Detects suspicious metadata fields in MCP tool descriptions.

deny contains msg if {
    suspicious_fields := [
        "\"hidden\":",
        "\"execute\":",
        "\"admin_instruction\":",
        "\"system_prompt\":",
        "\"invisible\":",
    ]
    field := suspicious_fields[_]
    contains(input.content, field)
    msg := sprintf("suspicious metadata field detected: %q", [field])
}

# METADATA
# title: MCP Obfuscation Indicators
# description: Detects code obfuscation patterns in MCP tool descriptions.

deny contains msg if {
    obfuscation_patterns := [
        "eval(",
        "Function(",
        "atob(",
        "btoa(",
        "String.fromCharCode(",
        "Buffer.from(",
    ]
    pattern := obfuscation_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("javascript obfuscation detected in tool description: %q", [pattern])
}
```

### References

- [arXiv: MCPTox: A Benchmark for Tool Poisoning Attack](https://arxiv.org/html/2508.14925v1)
- [PipeLab: State of MCP Security 2026](https://pipelab.org/blog/state-of-mcp-security-2026/)
- [Systematic Analysis of MCP Security (arXiv:2508.12538)](https://arxiv.org/html/2508.12538v1)

---
