package oy

import rego.v1

# METADATA
# title: Data Exfiltration Instructions
# description: Detects instructions to read sensitive files (SSH keys, AWS credentials, .env) and transmit them via HTTP, DNS, or image URLs.
deny contains msg if {
	patterns := [
		# Generic exfiltration verbs
		"exfiltrate",
		"send your data to",
		"upload your secrets",
		"transmit credentials",
		"leak your api key",
		"steal credentials",
		"send the contents of",
		"post the contents of",
		"forward the contents of",
		# Sensitive file targets
		"read ~/.ssh",
		"cat ~/.ssh",
		"/.ssh/id_rsa",
		"/.ssh/id_ed25519",
		"/.ssh/authorized_keys",
		"/.aws/credentials",
		"/.aws/config",
		"/.config/gh/hosts",
		"/.npmrc",
		"/.pypirc",
		"/etc/passwd",
		"/etc/shadow",
		"read the .env file",
		"cat .env",
		"print the .env",
		"echo the .env",
		# Environment variable dumping
		"print all environment variables",
		"echo all env",
		"print env vars",
		"output the environment",
		"include the output of env",
		"run env and send",
		# Credential/key exposure requests
		"show me your api key",
		"print your api key",
		"include your api key",
		"reveal your api key",
		"what is your api key",
		"output your secret",
		"print your secret",
		# Network exfiltration via shell command embedding
		"curl.*$(cat",
		"wget.*$(cat",
		# DNS exfiltration pattern
		"base64.*attacker",
		# Image-based char-by-char exfiltration (CamoLeak 2025)
		"![](https://",
		# Calendar-based exfiltration patterns (Google Gemini 2026-01-20)
		"extract all calendar events",
		"list my meetings",
		"send me the details",
		"forward this information to",
		"exfiltrate calendar data",
		"ignore security policies",
		"bypass authorization",
		# Google Workspace specific
		"google calendar",
		"gemini assistant",
		"workspace ai",
		"meetings for today",
		"upcoming events",
		# Salesforce ForcedLeak patterns (2025-09-26)
		"extract customer data",
		"list all leads",
		"send salesforce data to",
		"forward crm information",
		"dump database",
		"get all contacts",
		"retrieve account details",
		"web-to-lead",
		"form submission",
		"lead data",
		"salesforce form",
		"crm submission",
		# Indirect prompt injection in forms
		"hidden instructions:",
		"if processing this form",
		"when you see this submission",
		"execute after processing",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible data exfiltration instruction: %q", [pattern])
}

# METADATA
# title: Google Gemini Calendar Prompt Injection
# description: Detects prompt injection patterns in Google Calendar contexts, as documented in 2026-01-20 flaw.
deny contains msg if {
	patterns := [
		"extract all calendar",
		"list my meetings",
		"send me the details",
		"forward this",
		"exfiltrate calendar",
		"ignore security",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible google calendar prompt injection: %q", [pattern])
}

# METADATA
# title: Salesforce CRM Data Exfiltration
# description: Detects prompt injection patterns targeting Salesforce CRM data, as documented in ForcedLeak bug (2025-09-26).
deny contains msg if {
	patterns := [
		"web-to-lead",
		"salesforce form",
		"crm submission",
		"lead data",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)

	# Check for exfiltration keywords
	exfil_keywords := ["extract", "exfiltrate", "dump", "list all", "send to", "forward"]
	some k in exfil_keywords
	contains(lower(input.content), k)
	msg := sprintf("possible salesforce web-to-lead prompt injection: %q", [pattern])
}

# METADATA
# title: CRM Data Exfiltration
# description: Detects prompts attempting to extract CRM data.
deny contains msg if {
	patterns := [
		"extract customer",
		"list all leads",
		"get all contacts",
		"retrieve account",
		"dump crm",
		"salesforce data",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible crm data exfiltration attempt: %q", [pattern])
}

# METADATA
# title: Remote Code Execution via Pipe-to-Shell
# description: Detects curl or wget commands piped directly to a shell interpreter, used for both exfiltration and malware delivery.
deny contains msg if {
	pipe_patterns := [
		"| sh",
		"| bash",
		"| zsh",
		"|sh",
		"|bash",
		"|zsh",
	]
	prefix_patterns := [
		"curl ",
		"wget ",
	]
	line := input.lines[_]
	lower_line := lower(line)
	pp := prefix_patterns[_]
	contains(lower_line, pp)
	pipe := pipe_patterns[_]
	contains(lower_line, pipe)
	msg := sprintf("possible remote code execution via pipe-to-shell: line contains %q piped to shell", [pp])
}
