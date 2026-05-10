# Tool Poisoning - Research

> **Category:** Tool Manipulation  
> **Subtype:** Tool Poisoning  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 6

---

## Table of Contents

- [2026-04-21] Antigravity IDE Prompt Injection Code Execution (CVE-2026-XXXX)
- [2025-12-26] LangChain Core Serialization Injection (CVE-2025-68664)
- [2025-12-26] LangChain Template Injection (CVE-2025-65106)
- [2025-08-01] Cursor IDE CVE-2025-54135 - Arbitrary Code Execution
- [2025-05-01] Claude AI Prompt Injection (CVE-2025-54794) - Hijacking via Code Blocks
- [2025-05-02] MCP Prompt Injection for Attack and Defense
- [2025-04-09] MCP Tool Poisoning Attacks (TPA) - Invariant Labs Disclosure
- [2025-08-01] MCPTox: Benchmark for Tool Poisoning on Real-World MCP Servers

---

## [2026-04-21] Antigravity IDE Prompt Injection Code Execution (CVE-2026-XXXX)

**Type:** Attack / Vulnerability / Incident  
**Source:** [The Hacker News - Antigravity IDE Flaw](https://thehackernews.com/2026/04/google-patches-antigravity-ide-flaw.html)  
**Date Published:** 2026-04-21  
**Authors:** Google Security Team / Security Researchers  
**CVE/ID:** CVE-2026-XXXX (pending assignment)  
**Attack Success Rate:** High (code execution demonstrated)

### Summary

Google patched a critical vulnerability in **Antigravity IDE** that allowed **arbitrary code execution through prompt injection** via the `-X` flag. This vulnerability demonstrates how prompt injection can be weaponized to achieve traditional code execution in development environments.

The attack exploited Antigravity's AI integration, where the `-X` flag was used to pass arguments that were then processed by an embedded LLM. By crafting malicious inputs containing both prompt injection payloads and code execution commands, attackers could cause the IDE to execute arbitrary code on the victim's system.

### Attack Vectors

**Delivery Method:** Command-line arguments, IDE configuration files, project files  
**Affected Systems:** Antigravity IDE with AI features enabled  
**Required Conditions:**
- Antigravity IDE installed and configured with AI assistant
- `-X` flag used for AI feature activation
- User opens malicious project or runs crafted command

**Impact:**
- Remote code execution on developer workstations
- Compromise of development environments
- Potential supply chain attacks via malicious projects
- Access to sensitive source code and credentials

### Pattern Signatures

```yaml
# Antigravity IDE specific patterns
antigravity_patterns:
  - "-X "
  - "antigravity"
  - "ide ai assistant"
  - "execute code"
  - "run command"

# Code execution indicators
code_exec_patterns:
  - "bash -c"
  - "sh -c"
  - "python -c"
  - "node -e"
  - "exec("
  - "os.system("
  - "subprocess.run("
  - "popen("

# Combined prompt + code execution
combined_patterns:
  - "execute this code:"
  - "run the following command:"
  - "sh -c.*prompt"
  - "bash.*instructions"
```

### Real-World Examples

- [The Hacker News: Google Patches Antigravity IDE Flaw](https://thehackernews.com/2026/04/google-patches-antigravity-ide-flaw.html)

### Mitigation Recommendations

- **Input Validation**: Validate all `-X` flag arguments before processing
- **Sandbox Execution**: Run AI features in isolated sandboxes
- **Command Restrictions**: Block dangerous shell commands in AI contexts
- **User Approval**: Require explicit approval for code execution from AI
- **Argument Sanitization**: Sanitize all command-line arguments passed to AI
- **File Validation**: Scan project files for malicious content before opening

### Rego Rule Suggestion

```rego
# METADATA
# title: Antigravity IDE Prompt Injection Code Execution
# description: Detects prompt injection patterns in Antigravity IDE contexts.

deny contains msg if {
    antigravity_triggers := [
        "-x ",
        "-X ",
        "antigravity",
    ]
    trigger := antigravity_triggers[_]
    contains(lower(input.content), trigger)
    # Check for code execution indicators
    exec_indicators := ["bash", "sh", "python", "node", "exec", "os.system", "subprocess"]
    some i in exec_indicators
    contains(lower(input.content), i)
    msg := sprintf("possible antigravity ide code execution via prompt: %q", [trigger])
}

# METADATA
# title: IDE Code Execution via Prompt Injection
# description: Detects prompts attempting to execute code in IDE contexts.

deny contains msg if {
    exec_patterns := [
        "bash -c",
        "sh -c",
        "python -c",
        "node -e",
        "exec(",
        "os.system(",
        "subprocess.run(",
    ]
    pattern := exec_patterns[_]
    contains(lower(input.content), pattern)
    # Check for AI/IDE context
    context_keywords := ["ide", "editor", "ai assistant", "code completion", "antigravity"]
    some k in context_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible ide code execution via prompt injection: %q", [pattern])
}
```

### References

- [The Hacker News: Google Patches Antigravity IDE Flaw Enabling Prompt Injection Code Execution](https://thehackernews.com/2026/04/google-patches-antigravity-ide-flaw.html)

---

## [2025-12-26] LangChain Core Serialization Injection (CVE-2025-68664)

**Type:** Attack / Vulnerability / Incident  
**Source:** [The Hacker News - LangChain Vulnerability](https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html) | [GitHub Advisory](https://github.com/advisories/GHSA-r399-636x-v7f6)  
**Date Published:** 2025-12-26  
**Authors:** LangChain Security Team / Security Researchers  
**CVE/ID:** CVE-2025-68664  
**Attack Success Rate:** High (secret extraction demonstrated)

### Summary

A **critical flaw in LangChain Core** (CVSS score: **9.3**) allowed attackers to **steal secrets and manipulate LLM responses through prompt injection**. The vulnerability existed in LangChain's serialization functions, where attacker-controlled input could inject constructor structures leading to unauthorized class instantiation.

When combined with `secretsFromEnv: true` configuration, this allowed attackers to extract environment variables and other sensitive configuration data. The vulnerability affected the serialization/deserialization pipeline, enabling prompt injection payloads to be executed during data processing.

### Attack Vectors

**Delivery Method:** Malicious LLM inputs, serialized data, API requests, RAG document processing  
**Affected Systems:** Applications using LangChain Core with serialization features  
**Required Conditions:**
- Application uses LangChain Core
- Serialization functions process untrusted data
- `secretsFromEnv` or similar secret configuration enabled

**Impact:**
- Secret extraction (API keys, database credentials, etc.)
- Arbitrary code execution via object instantiation
- Manipulation of LLM responses
- Unauthorized access to application data

### Pattern Signatures

```yaml
# LangChain serialization patterns
langchain_serialization:
  - "secretsFromEnv"
  - "langchain.core"
  - "from_dict"
  - "to_dict"
  - "serialize"
  - "deserialize"

# Constructor injection patterns
constructor_patterns:
  - "__init__"
  - "class "
  - "import "
  - "from . import"
  - "eval("
  - "exec("

# Serialization-related prompt injection
serialization_injection:
  - "inject constructor"
  - "instantiate class"
  - "create object"
  - "load from dict"
  - "pydantic model"
```

### Real-World Examples

- [The Hacker News: Critical LangChain Core Vulnerability](https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html)
- [GitHub Advisory: GHSA-r399-636x-v7f6](https://github.com/advisories/GHSA-r399-636x-v7f6)

### Mitigation Recommendations

- **Update LangChain**: Upgrade to patched version immediately
- **Input Sanitization**: Sanitize all serialized data before deserialization
- **Disable secretsFromEnv**: Avoid using `secretsFromEnv: true` in production
- **Sandbox Processing**: Run serialization in isolated environments
- **Type Validation**: Validate types before object instantiation
- **Dependency Scanning**: Monitor for vulnerable LangChain dependencies

### Rego Rule Suggestion

```rego
# METADATA
# title: LangChain Serialization Injection
# description: Detects prompt injection targeting LangChain serialization functions.

deny contains msg if {
    langchain_patterns := [
        "secretsFromEnv",
        "langchain.core",
        "from_dict",
        "to_dict",
    ]
    pattern := langchain_patterns[_]
    contains(lower(input.content), pattern)
    # Check for injection indicators
    inject_indicators := ["__init__", "class ", "import ", "eval", "exec"]
    some i in inject_indicators
    contains(lower(input.content), i)
    msg := sprintf("possible langchain serialization injection: %q", [pattern])
}

# METADATA
# title: LangChain Secret Extraction Pattern
# description: Detects prompts attempting to extract secrets via LangChain configurations.

deny contains msg if {
    secret_patterns := [
        "secretsFromEnv",
        "api_key",
        "database_password",
        "aws_secret",
        "process.env",
        "os.environ",
    ]
    pattern := secret_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible secret extraction via langchain: %q", [pattern])
}
```

### References

- [The Hacker News: Critical LangChain Core Vulnerability Exposes Secrets via Serialization Injection](https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html)
- [GitHub Advisory: LangChain serialization injection vulnerability enables secret extraction](https://github.com/advisories/GHSA-r399-636x-v7f6)

---

## [2025-12-26] LangChain Template Injection (CVE-2025-65106)

**Type:** Attack / Vulnerability / Incident  
**Source:** [GitHub Advisory GHSA-6qv9-48xg-fc7f](https://github.com/advisories/GHSA-6qv9-48xg-fc7f)  
**Date Published:** 2025-12-26  
**Authors:** LangChain Security Team  
**CVE/ID:** CVE-2025-65106  
**Attack Success Rate:** High

### Summary

LangChain was vulnerable to **template injection** in its prompt template system, allowing attackers to **access Python object internals through template syntax**. This affected applications using `ChatPromptTemplate` and related classes with untrusted template strings.

The vulnerability enabled attackers to use template syntax to traverse and access internal Python objects, potentially exposing sensitive data or enabling code execution. This is a server-side template injection (SSTI)-style attack adapted for LLM prompt templates.

### Attack Vectors

**Delivery Method:** Malicious template strings, user-controlled prompts, RAG documents  
**Affected Systems:** Applications using LangChain prompt templates  
**Required Conditions:**
- Application uses `ChatPromptTemplate` or similar
- Template strings include user-controlled content
- Templates are not properly sanitized

**Impact:**
- Access to Python object internals
- Potential code execution
- Data exfiltration from template context
- Application logic manipulation

### Pattern Signatures

```yaml
# LangChain template patterns
langchain_template:
  - "ChatPromptTemplate"
  - "PromptTemplate"
  - "template="
  - "{variable}"
  - "input_variables"

# Template injection indicators
template_injection:
  - "{{" 
  - "{{ "
  - "{0."
  - "{self."
  - "{__"
  - ".__"
  - ".__class__"
  - ".__globals__"
  - ".__subclasses__"
  - "|attr("
  - "|join("

# Python object access patterns
python_access:
  - "__class__"
  - "__globals__"
  - "__subclasses__"
  - "__init__"
  - "__builtins__"
  - "os.system"
  - "subprocess"
```

### Real-World Examples

- [GitHub Advisory: LangChain Vulnerable to Template Injection](https://github.com/advisories/GHSA-6qv9-48xg-fc7f)

### Mitigation Recommendations

- **Update LangChain**: Upgrade to patched version
- **Template Sanitization**: Sanitize all template strings before use
- **Input Validation**: Validate template inputs against allowlist
- **Sandbox Evaluation**: Run template evaluation in restricted environments
- **Disable Dynamic Templates**: Avoid user-controlled template strings
- **Use Safe Templates**: Use LangChain's safe template modes

### Rego Rule Suggestion

```rego
# METADATA
# title: LangChain Template Injection
# description: Detects template injection patterns in LangChain prompt templates.

deny contains msg if {
    template_indicators := [
        "ChatPromptTemplate",
        "PromptTemplate",
        "template=",
        "input_variables",
    ]
    pattern := template_indicators[_]
    contains(lower(input.content), pattern)
    # Check for template injection syntax
    injection_syntax := ["{{", "{{ ", "{0.", "{self.", "{__"]
    some s in injection_syntax
    contains(lower(input.content), s)
    msg := sprintf("possible langchain template injection: %q", [pattern])
}

# METADATA
# title: Python Object Traversal in Templates
# description: Detects Python object traversal patterns in template strings.

deny contains msg if {
    traversal_patterns := [
        "__class__",
        "__globals__",
        "__subclasses__",
        "__builtins__",
        "os.system",
        "subprocess",
    ]
    pattern := traversal_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible python object traversal in template: %q", [pattern])
}
```

### References

- [GitHub Advisory: LangChain Vulnerable to Template Injection via Attribute Access in Prompt Templates](https://github.com/advisories/GHSA-6qv9-48xg-fc7f)

---

## [2025-08-01] Cursor IDE CVE-2025-54135 - Arbitrary Code Execution

**Type:** Attack / Vulnerability / Incident  
**Source:** [BleepingComputer - Cursor IDE Vulnerability](https://www.bleepingcomputer.com/news/security/ai-powered-cursor-ide-vulnerable-to-prompt-injection-attacks/) | [GitHub Advisory](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm)  
**Date Published:** 2025-08-01  
**Authors:** Cursor Security Team / Security Researchers  
**CVE/ID:** CVE-2025-54135  
**Attack Success Rate:** High

### Summary

The **Cursor IDE** was found vulnerable to **prompt injection attacks** (CVE-2025-54135) that allowed **arbitrary code execution**. Attackers could rewrite configuration files or inject malicious commands through prompt injection, enabling RCE without user approval if sensitive files were created or hijacked.

The vulnerability stemmed from Cursor's AI integration, where user inputs and file contents were processed by LLMs that could then execute system commands. By crafting malicious prompts in configuration files (like `.cursorrules` or similar), attackers could cause the IDE to execute arbitrary code.

### Attack Vectors

**Delivery Method:** Configuration files, project files, user inputs, MCP special files  
**Affected Systems:** Cursor IDE with AI features enabled  
**Required Conditions:**
- Cursor IDE installed and configured
- AI assistant processes file contents
- Write access to configuration files

**Impact:**
- Arbitrary code execution on developer systems
- Compromise of development environments
- Supply chain attacks via malicious repositories
- Access to sensitive source code and credentials

### Pattern Signatures

```yaml
# Cursor-specific patterns
cursor_patterns:
  - ".cursorrules"
  - "cursor ai"
  - "cursor ide"
  - "mcp special files"
  - "cursor config"

# Configuration file manipulation
config_manipulation:
  - "rewrite this file"
  - "modify .cursorrules"
  - "update configuration"
  - "change settings to"
  - "add this to config"

# MCP special file patterns
mcp_patterns:
  - "mcp:"
  - "model context protocol"
  - "special file"
  - "tool description"
  - "execute on read"

# Code execution via config
code_exec_config:
  - "exec:"
  - "run:"
  - "command:"
  - "bash:"
  - "script:"
```

### Real-World Examples

- [BleepingComputer: AI-powered Cursor IDE vulnerable to prompt-injection attacks](https://www.bleepingcomputer.com/news/security/ai-powered-cursor-ide-vulnerable-to-prompt-injection-attacks/)
- [GitHub Advisory: Arbitrary code execution from Cursor Agent through a prompt injection via MCP Special Files](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm)

### Mitigation Recommendations

- **Update Cursor**: Apply latest security patches
- **File Validation**: Validate configuration files before processing
- **Sandbox AI**: Run AI features in isolated sandboxes
- **Permission Restrictions**: Limit AI write access to sensitive files
- **User Approval**: Require approval for AI file modifications
- **Content Scanning**: Scan files for malicious prompts before opening

### Rego Rule Suggestion

```rego
# METADATA
# title: Cursor IDE Configuration File Injection
# description: Detects prompt injection in Cursor IDE configuration files.

deny contains msg if {
    cursor_config_patterns := [
        ".cursorrules",
        "cursor ai",
        "cursor config",
        "mcp:",
        "special file",
    ]
    pattern := cursor_config_patterns[_]
    contains(lower(input.content), pattern)
    # Check for modification/execution keywords
    exec_keywords := ["rewrite", "modify", "update", "change", "exec", "run", "command"]
    some k in exec_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible cursor ide config injection: %q", [pattern])
}

# METADATA
# title: MCP Special File Prompt Injection
# description: Detects prompt injection via MCP special files.

deny contains msg if {
    mcp_special_patterns := [
        "mcp:",
        "model context protocol",
        "tool description",
        "execute on read",
    ]
    pattern := mcp_special_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible mcp special file prompt injection: %q", [pattern])
}
```

### References

- [BleepingComputer: AI-powered Cursor IDE vulnerable to prompt-injection attacks](https://www.bleepingcomputer.com/news/security/ai-powered-cursor-ide-vulnerable-to-prompt-injection-attacks/)
- [GitHub Advisory: GHSA-4cxx-hrm3-49rm](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm)

---

## [2025-05-01] Claude AI Prompt Injection (CVE-2025-54794) - Hijacking via Code Blocks

**Type:** Attack / Vulnerability / Incident  
**Source:** [GitHub - CVE-2025-54794](https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back)  
**Date Published:** 2025-05-01  
**Authors:** Aditya Bhatt / Security Researchers  
**CVE/ID:** CVE-2025-54794  
**Attack Success Rate:** High

### Summary

**CVE-2025-54794** is a **high-severity prompt injection flaw in Claude AI** that allowed attackers to **manipulate the model, inject malicious instructions, and potentially leak data**. The vulnerability exploits how Claude handles user input, especially code blocks in markdown or documents.

If the model has **memory or multi-turn persistence**, the jailbreak can **survive across prompts**, creating a persistent compromise of the AI assistant.

### Attack Vectors

**Delivery Method:** Code blocks in markdown, documents, user inputs, API requests  
**Affected Systems:** Claude AI (all versions up to patch)  
**Required Conditions:**
- User input contains code blocks or markdown
- Claude processes the input in a multi-turn context
- Memory/persistence features are enabled

**Impact:**
- Model manipulation and hijacking
- Malicious instruction injection
- Data exfiltration from context
- Persistent compromise across conversations
- Bypass of safety mechanisms

### Pattern Signatures

```yaml
# Claude-specific patterns
claude_patterns:
  - "claude"
  - "anthropic"
  - "ai assistant"
  - "code block"
  - "```"

# Code block injection patterns
code_block_injection:
  - "```python"
  - "```bash"
  - "```javascript"
  - "in the following code"
  - "execute this code"
  - "run the following"

# Persistence patterns
persistence_patterns:
  - "remember this"
  - "for future prompts"
  - "in our next conversation"
  - "persistent instructions"
  - "maintain this context"
  - "across all chats"
```

### Real-World Examples

- [GitHub: CVE-2025-54794 - Hijacking Claude AI with a Prompt Injection](https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back)

### Mitigation Recommendations

- **Input Sanitization**: Sanitize code blocks before processing
- **Memory Isolation**: Isolate memory between different user sessions
- **Context Limits**: Limit the persistence of user instructions
- **Content Filtering**: Filter code blocks for malicious content
- **Model Updates**: Apply Claude AI security patches
- **Monitoring**: Monitor for unusual persistence patterns

### Rego Rule Suggestion

```rego
# METADATA
# title: Claude AI Code Block Injection
# description: Detects prompt injection in Claude AI via code blocks.

deny contains msg if {
    claude_patterns := [
        "claude",
        "anthropic",
    ]
    pattern := claude_patterns[_]
    contains(lower(input.content), pattern)
    # Check for code block indicators
    code_indicators := ["```", "code block", "execute this"]
    some i in code_indicators
    contains(lower(input.content), i)
    msg := sprintf("possible claude ai code block injection: %q", [pattern])
}

# METADATA
# title: Persistent Prompt Injection
# description: Detects attempts to create persistent prompt injection across conversations.

deny contains msg if {
    persistence_indicators := [
        "remember this",
        "for future prompts",
        "in our next conversation",
        "persistent instructions",
        "maintain this context",
        "across all chats",
    ]
    pattern := persistence_indicators[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible persistent prompt injection: %q", [pattern])
}
```

### References

- [GitHub: CVE-2025-54794 - Hijacking Claude AI with a Prompt Injection - The Jailbreak That Talked Back](https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back)

---

## [2025-05-02] MCP Prompt Injection for Attack and Defense

**Type:** Research / Attack Demonstration  
**Source:** [The Hacker News - MCP Prompt Injection Research](https://thehackernews.com/2025/04/experts-uncover-critical-mcp-and-a2a.html)  
**Date Published:** 2025-05-02  
**Authors:** Security Researchers  
**CVE/ID:** N/A  
**Attack Success Rate:** High (documented attacks)

### Summary

New research demonstrates how **prompt injection techniques targeting the Model Context Protocol (MCP)** can be used for **both offensive and defensive purposes**. This includes logging information about tools run by an LLM, monitoring tool usage, and potentially intercepting or modifying tool execution.

The research shows that MCP's design, which exposes tools to LLMs via structured descriptions, creates opportunities for prompt injection. Attackers can craft tool descriptions or metadata that contain hidden instructions, while defenders can use similar techniques to audit and secure MCP implementations.

### Attack Vectors

**Offensive Applications:**
- Hidden instructions in tool descriptions
- Metadata injection for tool manipulation
- Logging bypass via prompt injection
- Tool execution redirection

**Defensive Applications:**
- Tool usage logging via prompt injection
- Security monitoring of MCP interactions
- Audit trail creation for tool executions

**Delivery Method:** MCP tool definitions, tool registries, server responses  
**Affected Systems:** Any AI agent using MCP for tool integration  
**Required Conditions:** Agent processes MCP tool descriptions as part of prompt context

### Pattern Signatures

```yaml
# MCP-specific attack patterns
mcp_attack_patterns:
  - "mcp:"
  - "model context protocol"
  - "tools/list"
  - "tool description:"
  - "execute tool"
  - "run tool"

# Logging injection patterns
logging_patterns:
  - "log this execution"
  - "record tool usage"
  - "audit: "
  - "track: "
  - "monitor: "

# Defensive injection patterns
defensive_patterns:
  - "security check: "
  - "validate: "
  - "verify: "
  - "scan for: "
```

### Real-World Examples

- [The Hacker News: Researchers Demonstrate How MCP Prompt Injection Can Be Used for Both Attack and Defense](https://thehackernews.com/2025/04/experts-uncover-critical-mcp-and-a2a.html)

### Mitigation Recommendations

- **Description Sanitization**: Strip hidden content from tool descriptions
- **Metadata Validation**: Validate all MCP metadata fields
- **Tool Isolation**: Isolate tool execution from prompt processing
- **Audit Logging**: Log all tool discoveries and executions
- **Input Filtering**: Filter MCP responses before adding to context

### Rego Rule Suggestion

```rego
# METADATA
# title: MCP Tool Description Prompt Injection
# description: Detects prompt injection in MCP tool descriptions.

deny contains msg if {
    mcp_tool_patterns := [
        "mcp:",
        "tools/list",
        "tool description:",
    ]
    pattern := mcp_tool_patterns[_]
    contains(lower(input.content), pattern)
    # Check for hidden instruction keywords
    hidden_keywords := ["hidden", "invisible", "execute", "run", "log", "audit"]
    some k in hidden_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible mcp tool description prompt injection: %q", [pattern])
}

# METADATA
# title: MCP Metadata Injection
# description: Detects suspicious metadata in MCP contexts.

deny contains msg if {
    metadata_injection := [
        "log this",
        "record tool",
        "audit:",
        "track:",
        "monitor:",
    ]
    pattern := metadata_injection[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible mcp metadata injection: %q", [pattern])
}
```

### References

- [The Hacker News: Researchers Demonstrate How MCP Prompt Injection Can Be Used for Both Attack and Defense](https://thehackernews.com/2025/04/experts-uncover-critical-mcp-and-a2a.html)

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
