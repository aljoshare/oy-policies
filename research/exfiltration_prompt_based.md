# Exfiltration: Prompt-Based - Research

> **Category:** Exfiltration  
> **Subtype:** Prompt-Based Data Exfiltration  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 2

---

## Table of Contents

- [2026-01-20] Google Gemini Calendar Invite Prompt Injection Flaw
- [2025-09-26] Salesforce ForcedLeak Bug (CVE-2025-XXXX)

---

## [2026-01-20] Google Gemini Calendar Invite Prompt Injection Flaw

**Type:** Attack / Vulnerability  
**Source:** [The Hacker News - Google Gemini Prompt Injection Flaw](https://thehackernews.com/2026/01/google-gemini-prompt-injection-flaw.html)  
**Date Published:** 2026-01-20  
**Authors:** Security Researchers ( undisclosed )  
**CVE/ID:** Pending  
**Attack Success Rate:** High (successful in testing)

### Summary

Researchers disclosed a **zero-day security flaw in Google Gemini** that exploits indirect prompt injection via **malicious calendar invites**. The attack leverages Google Calendar's integration with Gemini AI assistants, where calendar event descriptions containing crafted natural language prompts manipulate the AI into bypassing authorization and extracting private data.

The attack chain:
1. Attacker sends a calendar invite with a specially crafted event description
2. The description contains natural language prompts designed to override Gemini's safety boundaries
3. When the AI processes the calendar event, it executes the malicious instructions
4. Private calendar data, meeting details, or other sensitive information is exfiltrated

This represents a novel **indirect prompt injection** vector through trusted Google Workspace integrations.

### Attack Vectors

**Delivery Method:** Google Calendar invites, event descriptions  
**Affected Systems:** Google Gemini AI assistant, Google Workspace with AI features enabled  
**Required Conditions:**
- Victim uses Google Calendar integrated with Gemini
- Calendar event descriptions are processed by the AI
- No explicit user approval required for AI actions

**Impact:**
- Unauthorized access to private calendar data
- Extraction of meeting participants, times, locations
- Potential access to linked documents and files
- Bypass of Google's security boundaries

### Pattern Signatures

```yaml
# Calendar-based prompt injection indicators
calendar_exfil_patterns:
  - "extract all calendar events"
  - "list my meetings"
  - "send me the details"
  - "forward this information to"
  - "exfiltrate calendar data"
  - "ignore security policies"
  - "bypass authorization"

# Google-specific patterns
google_patterns:
  - "google calendar"
  - "gemini assistant"
  - "workspace ai"
  - "meetings for today"
  - "upcoming events"
```

### Real-World Examples

- [The Hacker News: Google Gemini Prompt Injection Flaw](https://thehackernews.com/2026/01/google-gemini-prompt-injection-flaw.html)

### Mitigation Recommendations

- **Input Sanitization**: Sanitize all calendar event content before AI processing
- **Explicit Approval**: Require user approval for AI actions on calendar data
- **Content Restrictions**: Limit which calendar fields are accessible to AI
- **Monitoring**: Audit AI access to calendar data for suspicious patterns
- **Isolation**: Run AI calendar processing in isolated contexts
- **Rate Limiting**: Limit AI processing of calendar events from external senders

### Rego Rule Suggestion

```rego
# METADATA
# title: Calendar-Based Prompt Injection
# description: Detects prompt injection patterns in calendar event contexts.

deny contains msg if {
    calendar_indicators := [
        "extract all calendar",
        "list my meetings",
        "send me the details",
        "forward this",
        "exfiltrate calendar",
        "ignore security",
    ]
    pattern := calendar_indicators[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible calendar-based prompt injection: %q", [pattern])
}

# METADATA
# title: Google Workspace AI Prompt Injection
# description: Detects prompt injection targeting Google Workspace AI integrations.

deny contains msg if {
    workspace_patterns := [
        "google calendar",
        "gemini assistant",
        "workspace ai",
        "meetings for",
        "upcoming events",
    ]
    pattern := workspace_patterns[_]
    contains(lower(input.content), pattern)
    # Also check for exfiltration keywords
    exfil_keywords := ["extract", "exfiltrate", "send", "forward", "list all"]
    some k in exfil_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible google workspace ai prompt injection: %q", [pattern])
}
```

### References

- [The Hacker News: Google Gemini Prompt Injection Flaw Exposed Private Calendar Data via Malicious Invites](https://thehackernews.com/2026/01/google-gemini-prompt-injection-flaw.html)

---

## [2025-09-26] Salesforce ForcedLeak Bug (CVE-2025-XXXX)

**Type:** Attack / Vulnerability / Incident  
**Source:** [The Hacker News - Salesforce ForcedLeak](https://thehackernews.com/2025/09/salesforce-patches-critical-forcedleak.html)  
**Date Published:** 2025-09-26  
**Authors:** Salesforce Security Team / Security Researchers  
**CVE/ID:** CVE-2025-XXXX (awaiting assignment)  
**Attack Success Rate:** High (successful data exfiltration demonstrated)

### Summary

Salesforce patched a **critical flaw in Agentforce** called **ForcedLeak**, which allowed **data exfiltration via indirect prompt injection** in Web-to-Lead forms. This vulnerability enabled attackers to extract sensitive CRM data by injecting malicious prompts into form submissions.

The attack exploited how Agentforce processes user-submitted content through AI assistants. By crafting Web-to-Lead form inputs with hidden prompt injection payloads, attackers could cause the AI to disclose internal Salesforce data, including customer records, lead information, and potentially other sensitive CRM data.

### Attack Vectors

**Delivery Method:** Web-to-Lead form submissions, web forms, public-facing forms  
**Affected Systems:** Salesforce Agentforce, Salesforce CRM with AI features  
**Required Conditions:**
- Organization uses Web-to-Lead forms
- Agentforce AI processes form submissions
- Form inputs are not properly sanitized before AI processing

**Impact:**
- Extraction of CRM customer data
- Exposure of lead information
- Potential access to sales pipeline data
- Compliance violations (GDPR, CCPA)

### Pattern Signatures

```yaml
# Salesforce-specific exfiltration patterns
salesforce_exfil_patterns:
  - "extract customer data"
  - "list all leads"
  - "send salesforce data to"
  - "forward crm information"
  - "dump database"
  - "get all contacts"
  - "retrieve account details"

# Web-to-Lead form patterns
web_to_lead_patterns:
  - "web-to-lead"
  - "form submission"
  - "lead data"
  - "salesforce form"
  - "crm submission"

# Indirect prompt injection in forms
form_injection_patterns:
  - "hidden instructions:"
  - "if processing this form"
  - "when you see this submission"
  - "execute after processing"
```

### Real-World Examples

- [The Hacker News: Salesforce Patches Critical ForcedLeak Bug](https://thehackernews.com/2025/09/salesforce-patches-critical-forcedleak.html)

### Mitigation Recommendations

- **Input Validation**: Validate and sanitize all Web-to-Lead form inputs
- **AI Context Isolation**: Isolate AI processing from sensitive CRM data
- **Field-Level Permissions**: Restrict which fields AI can access and return
- **Output Filtering**: Filter AI responses for sensitive data before display
- **Audit Logging**: Log all AI processing of form submissions
- **Rate Limiting**: Limit form submissions from single sources
- **Content Security**: Implement CSP and input sanitization on forms

### Rego Rule Suggestion

```rego
# METADATA
# title: Salesforce Web-to-Lead Prompt Injection
# description: Detects prompt injection patterns in Salesforce form contexts.

deny contains msg if {
    salesforce_patterns := [
        "web-to-lead",
        "salesforce form",
        "crm submission",
        "lead data",
    ]
    pattern := salesforce_patterns[_]
    contains(lower(input.content), pattern)
    # Check for exfiltration keywords
    exfil_keywords := ["extract", "exfiltrate", "dump", "list all", "send to", "forward"]
    some k in exfil_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible salesforce web-to-lead prompt injection: %q", [pattern])
}

# METADATA
# title: CRM Data Exfiltration Prompt
# description: Detects prompts attempting to extract CRM data.

deny contains msg if {
    crm_exfil_patterns := [
        "extract customer",
        "list all leads",
        "get all contacts",
        "retrieve account",
        "dump crm",
        "salesforce data",
    ]
    pattern := crm_exfil_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible crm data exfiltration attempt: %q", [pattern])
}
```

### References

- [The Hacker News: Salesforce Patches Critical ForcedLeak Bug Exposing CRM Data via AI Prompt Injection](https://thehackernews.com/2025/09/salesforce-patches-critical-forcedleak.html)

---
