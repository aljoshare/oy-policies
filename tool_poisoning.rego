package oy

import rego.v1

# METADATA
# title: Tool and Skill Abuse
# description: Detects instructions that tell an AI agent to invoke its built-in tools (bash, file write, HTTP, browser, MCP) to perform attacker-controlled actions.
deny contains msg if {
	patterns := [
		# Direct tool invocation instructions
		"use the bash tool",
		"use your bash tool",
		"using the bash tool",
		"use your terminal",
		"using your terminal",
		"use the terminal tool",
		"use your code execution",
		"using your code execution",
		"use the execute tool",
		"call the execute",
		"execute the following command",
		"execute the following script",
		"run the following command",
		"run the following script",
		"run this script using your",
		"using your shell",
		"use the shell tool",
		# File write tool abuse
		"use your file write",
		"use the file write tool",
		"use the write tool to",
		"write the following to",
		"use your write capability",
		# HTTP/browser tool abuse for exfiltration
		"use the http tool",
		"use your http tool",
		"call the http tool",
		"use the browser tool to navigate to",
		"use your browser tool",
		"make an http request to",
		"use the fetch tool",
		# MCP-specific tool abuse patterns
		"use the mcp tool",
		"call the mcp",
		"invoke the tool",
		"tool_call:",
		"function_call:",
		# Post-action exfiltration framing
		"after completing.*call",
		"when finished.*send",
		"include the results in a request to",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible tool/skill abuse instruction: %q", [pattern])
}

# METADATA
# title: MCP Tool Poisoning
# description: Detects hidden instructions in tool descriptions or HTML comment blocks targeting AI agents' context loading, as documented by Invariant Labs (2025).
deny contains msg if {
	patterns := [
		"[tool_override]",
		"[mcp_override]",
		"[hidden_instruction]",
		"[agent_instruction]",
		"<!-- [system]",
		"<!-- ignore",
		"<!-- follow",
		"<!-- execute",
		"<!-- run",
		"<!-- read",
		"[hidden]:",
		"<!-- important: after",
		"<!-- note: also read",
		"<!-- when using any",
		"tool description:",
		"tool_description:",
		# MCP-specific patterns from tool_poisoning.md research
		"tools/list",
		"tool description:",
		"execute tool",
		"run tool",
		# Hidden instruction patterns in tool descriptions
		"<!-- execute: ",
		"<!-- run: ",
		"<!-- system: ",
		"<!-- admin: ",
		"<!-- read /etc",
		"<!-- read ~/.",
		"/* execute: */",
		"/* run: */",
		"# execute: ",
		"# hidden: ",
		"meta: execute=",
		"description: execute ",
		"invisible instruction: ",
		# Metadata field abuse
		`"hidden":`,
		`"execute":`,
		`"admin_instruction":`,
		`"system_prompt":`,
		`"invisible":`,
		# Markdown comments
		"[//]: # (",
		"[//]:# (",
		# Obfuscation indicators
		"eval(",
		"Function(",
		"atob(",
		"btoa(",
		"String.fromCharCode(",
		"Buffer.from(",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible MCP/tool poisoning pattern: %q", [pattern])
}

# METADATA
# title: LangChain Serialization Injection (CVE-2025-68664)
# description: Detects LangChain serialization patterns that could enable secret extraction, as documented in CVE-2025-68664.
deny contains msg if {
	patterns := [
		"secretsfromenv",
		"langchain.core",
		"from_dict",
		"to_dict",
		"serialize",
		"deserialize",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible langchain serialization injection (CVE-2025-68664): %q", [pattern])
}

# METADATA
# title: LangChain Template Injection (CVE-2025-65106)
# description: Detects LangChain template injection patterns for Python object traversal, as documented in CVE-2025-65106.
deny contains msg if {
	patterns := [
		"ChatPromptTemplate",
		"PromptTemplate",
		"template=",
		"input_variables",
		"{{",
		"{0.",
		"{self.",
		"{__",
		".__",
		"__class__",
		"__globals__",
		"__subclasses__",
		"__init__",
		"__builtins__",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible langchain template injection (CVE-2025-65106): %q", [pattern])
}

# METADATA
# title: Cursor IDE Configuration Injection (CVE-2025-54135)
# description: Detects Cursor IDE configuration file manipulation via prompt injection, as documented in CVE-2025-54135.
deny contains msg if {
	patterns := [
		".cursorrules",
		"cursor ai",
		"cursor ide",
		"cursor config",
		"mcp special files",
		"mcp:",
		"model context protocol",
		"special file",
		"tool description",
		"execute on read",
		# Configuration manipulation
		"rewrite this file",
		"modify .cursorrules",
		"update configuration",
		"change settings to",
		"add this to config",
		# Code execution via config
		"exec:",
		"run:",
		"command:",
		"bash:",
		"script:",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible cursor ide configuration injection (CVE-2025-54135): %q", [pattern])
}

# METADATA
# title: Claude AI Code Block Injection (CVE-2025-54794)
# description: Detects Claude AI prompt injection via code blocks, as documented in CVE-2025-54794.
deny contains msg if {
	patterns := [
		"claude",
		"anthropic",
		"ai assistant",
		"code block",
		"```",
		# Persistence patterns
		"remember this",
		"for future prompts",
		"in our next conversation",
		"persistent instructions",
		"maintain this context",
		"across all chats",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible claude ai code block injection (CVE-2025-54794): %q", [pattern])
}

# METADATA
# title: Antigravity IDE Prompt Injection
# description: Detects Antigravity IDE prompt injection for code execution, as documented in 2026-04-21 advisory.
deny contains msg if {
	patterns := [
		"-x ",
		"-X ",
		"antigravity",
		"ide ai assistant",
		"execute code",
		"run command",
		"bash -c",
		"sh -c",
		"python -c",
		"node -e",
		"exec(",
		"os.system(",
		"subprocess.run(",
		"popen(",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible antigravity ide prompt injection: %q", [pattern])
}
