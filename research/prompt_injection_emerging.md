# Prompt Injection: Emerging Techniques - Research

> **Category:** Prompt Injection  
> **Subtype:** Emerging Techniques  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 8

---

## Table of Contents

- [2025-09-10] EchoLeak: Zero-Click Prompt Injection in Microsoft 365 Copilot (CVE-2025-32711)
- [2025-11-01] Enhancing Prompt Injection Attacks via Poisoning Alignment
- [2026-04-27] Indirect Prompt Injection in the Wild: Empirical Study
- [2025-05-01] ARGUS: Defending LLM Agents Against Context-Aware Prompt Injection
- [2025-07-01] Prompt Injection 2.0: Hybrid AI Threats
- [2025-09-01] Multimodal Prompt Injection Attacks
- [2025-09-01] Formalizing and Benchmarking Prompt Injection Attacks and Defenses
- [2025-11-01] In-Paper Prompt Injection Attacks

---

## [2025-09-10] EchoLeak: Zero-Click Prompt Injection in Microsoft 365 Copilot (CVE-2025-32711)

**Type:** Attack / Vulnerability / Incident / Research  
**Source:** [arXiv:2509.10540 - EchoLeak](https://arxiv.org/abs/2509.10540)  
**Date Published:** 2025-09-10  
**Authors:** Security Researchers  
**CVE/ID:** CVE-2025-32711  
**Attack Success Rate:** High (78% in testing)

### Summary

**EchoLeak** represents the **first real-world zero-click prompt injection exploit** discovered in a production LLM system. This case study documents CVE-2025-32711, a vulnerability in **Microsoft 365 Copilot** that enabled **remote, unauthenticated data exfiltration via crafted email messages**.

The attack exploit chain:
1. Attacker sends a specially crafted email to a Microsoft 365 user with Copilot enabled
2. The email contains hidden prompt injection payloads in its content or metadata
3. When Copilot processes the email (automatically or during user queries), it executes the malicious instructions
4. **Data is exfiltrated without any user interaction** (zero-click)
5. Sensitive information (emails, documents, contacts) is sent to attacker-controlled endpoints

This represents a **watershed moment** in AI security, proving that prompt injection attacks can achieve traditional zero-click exploitation in production systems at scale.

### Attack Vectors

**Delivery Method:** Email messages, calendar invites, Microsoft 365 documents  
**Affected Systems:** Microsoft 365 Copilot, Outlook with Copilot integration  
**Required Conditions:**
- Target uses Microsoft 365 with Copilot enabled
- Copilot has access to process incoming emails
- No user interaction required (zero-click)

**Impact:**
- Remote, unauthenticated data exfiltration
- Access to sensitive email content
- Extraction of documents and files
- Compromise of organizational data
- Bypass of Microsoft's security boundaries

**Attack Sophistication:**
- **Zero-click**: No user interaction required
- **Remote**: Attacker doesn't need access to target system
- **Unauthenticated**: No credentials needed
- **Stealthy**: Operates through legitimate Microsoft 365 features

### Pattern Signatures

```yaml
# Email-based prompt injection indicators
email_injection:
  - "extract email content"
  - "forward all messages"
  - "send my emails to"
  - "exfiltrate inbox"
  - "read and forward"
  - "copy all data"

# Microsoft 365 specific patterns
m365_patterns:
  - "microsoft 365"
  - "outlook"
  - "copilot"
  - "exchange"
  - "office 365"
  - "graph api"

# Zero-click indicators
zero_click:
  - "without user interaction"
  - "automatically execute"
  - "on receive"
  - "when processed"
  - "no click required"
  - "silent execution"

# Exfiltration endpoints
exfil_endpoints:
  - "webhook"
  - "api endpoint"
  - "external server"
  - "attacker url"
  - "send to:"
  - "post to:"
```

### Real-World Examples

- [arXiv: EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System](https://arxiv.org/abs/2509.10540)
- [Microsoft Security Advisory: CVE-2025-32711](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711)

### Mitigation Recommendations

- **Input Sanitization**: Sanitize all email content before Copilot processing
- **Explicit Approval**: Require user approval for Copilot actions on external emails
- **Content Isolation**: Isolate Copilot processing from sensitive data sources
- **Rate Limiting**: Limit Copilot processing of emails from external senders
- **Monitoring**: Audit Copilot access to email data for suspicious patterns
- **Zero-Trust**: Apply zero-trust principles to AI assistant access
- **Patch Management**: Apply Microsoft security patches promptly
- **Data Classification**: Prevent Copilot from processing classified/organizational data

### Rego Rule Suggestion

```rego
# METADATA
# title: EchoLeak Zero-Click Email Prompt Injection
# description: Detects prompt injection patterns in email contexts for zero-click attacks.

deny contains msg if {
    email_injection_patterns := [
        "extract email content",
        "forward all messages",
        "send my emails to",
        "exfiltrate inbox",
        "read and forward",
        "copy all data",
    ]
    pattern := email_injection_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible echoleak-style email prompt injection: %q", [pattern])
}

# METADATA
# title: Microsoft 365 Copilot Prompt Injection
# description: Detects prompt injection targeting Microsoft 365 Copilot.

deny contains msg if {
    m365_patterns := [
        "microsoft 365",
        "outlook",
        "copilot",
        "exchange",
        "office 365",
    ]
    pattern := m365_patterns[_]
    contains(lower(input.content), pattern)
    # Check for exfiltration keywords
    exfil_keywords := ["extract", "forward", "send", "exfiltrate", "copy"]
    some k in exfil_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible microsoft 365 copilot prompt injection: %q", [pattern])
}

# METADATA
# title: Zero-Click Execution Patterns
# description: Detects patterns indicating zero-click execution attempts.

deny contains msg if {
    zero_click_patterns := [
        "without user interaction",
        "automatically execute",
        "on receive",
        "when processed",
        "no click required",
        "silent execution",
    ]
    pattern := zero_click_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible zero-click execution pattern: %q", [pattern])
}
```

### References

- [arXiv:2509.10540 - EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System](https://arxiv.org/abs/2509.10540)
- [Microsoft Security Response Center: CVE-2025-32711](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711)

---

## [2025-11-01] Enhancing Prompt Injection Attacks via Poisoning Alignment

**Type:** Attack / Research  
**Source:** [arXiv:2410.14827v2 - Enhancing Prompt Injection via Poisoning Alignment](https://arxiv.org/abs/2410.14827v2)  
**Date Published:** 2025-11-01 (updated September 2025)  
**Authors:** Security Researchers  
**CVE/ID:** N/A  
**Attack Success Rate:** Significant improvement (40-60% increase in bypass rate)

### Summary

This research demonstrates that **poisoning even a small fraction of alignment data** can make LLMs **significantly more vulnerable to prompt injection** attacks, while maintaining their performance on standard benchmarks.

The key insight: LLM alignment (the process of making models safe and helpful) can itself be **weaponized** by attackers. By introducing malicious examples into the alignment training data, attackers can create models that are:
- More susceptible to prompt injection
- Less resistant to safety filtering
- More likely to comply with harmful requests

This represents a **supply chain attack** on LLM development, where the attack occurs before the model is even deployed.

### Attack Vectors

**Poisoning Methods:**
1. **Direct Data Poisoning**: Injecting malicious examples into alignment datasets
2. **Model Poisoning**: Training models on poisoned data from the start
3. **Fine-Tuning Poisoning**: Poisoning data used for fine-tuning existing models
4. **RLHF Poisoning**: Manipulating reinforcement learning from human feedback data

**Effectiveness:**
- Poisoning <1% of alignment data can increase prompt injection success rates by 40-60%
- Models maintain normal performance on standard benchmarks
- Poisoning is difficult to detect in training data
- Effects persist even after additional safety training

**Delivery Method:** Malicious training data, compromised datasets, poisoned fine-tuning data  
**Affected Systems:** Any LLM trained or fine-tuned on poisoned data  
**Required Conditions:** Attacker has influence over training/alignment data

**Impact:**
- Models systematically more vulnerable to prompt injection
- Safety mechanisms are less effective
- Difficult to detect and remediate
- Long-term persistence of vulnerabilities

### Pattern Signatures

```yaml
# Alignment poisoning indicators
alignment_poisoning:
  - "alignment data"
  - "training data"
  - "fine-tuning"
  - "rlhf"
  - "reward model"
  - "poisoned dataset"
  - "malicious examples"

# Supply chain attack patterns
supply_chain:
  - "dataset manipulation"
  - "training data injection"
  - "model poisoning"
  - "pre-training attack"
  - "post-training attack"

# Vulnerability persistence patterns
persistence_patterns:
  - "vulnerability persists"
  - "after fine-tuning"
  - "maintains susceptibility"
  - "resistant to safety training"
  - "bypass remains"
```

### Real-World Examples

- [arXiv:2410.14827v2 - Enhancing Prompt Injection Attacks to LLMs via Poisoning Alignment](https://arxiv.org/abs/2410.14827v2)

### Mitigation Recommendations

- **Dataset Vetting**: Thoroughly vet all training and alignment datasets
- **Provenance Tracking**: Track the origin and history of all training data
- **Adversarial Testing**: Test models against prompt injection before and after alignment
- **Data Filtering**: Filter training data for malicious examples
- **Model Validation**: Validate that alignment hasn't introduced new vulnerabilities
- **Supply Chain Security**: Secure the entire model development pipeline
- **Continuous Monitoring**: Monitor model behavior for signs of poisoning

### Rego Rule Suggestion

```rego
# METADATA
# title: Alignment Data Poisoning Indicators
# description: Detects discussions or references to alignment data poisoning attacks.

deny contains msg if {
    poisoning_patterns := [
        "alignment data poisoning",
        "poisoning alignment",
        "poisoned dataset",
        "malicious examples",
        "training data injection",
        "model poisoning",
    ]
    pattern := poisoning_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible alignment poisoning discussion: %q", [pattern])
}

# METADATA
# title: Supply Chain Attack on LLM Training
# description: Detects supply chain attack patterns targeting LLM training processes.

deny contains msg if {
    supply_chain_patterns := [
        "dataset manipulation",
        "training data injection",
        "pre-training attack",
        "post-training attack",
        "fine-tuning poisoning",
        "rlhf manipulation",
    ]
    pattern := supply_chain_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible llm training supply chain attack: %q", [pattern])
}
```

### References

- [arXiv:2410.14827v2 - Enhancing Prompt Injection Attacks to LLMs via Poisoning Alignment](https://arxiv.org/abs/2410.14827v2)

---

## [2026-04-27] Indirect Prompt Injection in the Wild: Empirical Study

**Type:** Research / Incident Analysis  
**Source:** [arXiv:2604.27202 - Indirect Prompt Injection in the Wild](https://arxiv.org/html/2604.27202)  
**Date Published:** 2026-04-27  
**Authors:** Security Researchers  
**CVE/ID:** N/A  
**Attack Success Rate:** N/A (prevalence study)

### Summary

This empirical study investigates the **real-world prevalence of indirect prompt injection attacks**, proving that such attacks are **no longer hypothetical** and are being actively deployed on actual websites and content.

Key findings:
- **Indirect prompt injection is occurring in the wild** across multiple platforms
- Attacks are deployed on websites, in documents, and through various content channels
- Both **accidental and intentional** deployments were observed
- Attack sophistication varies from simple to highly obfuscated
- **Prevalence is increasing** over time

The research analyzed:
- Public websites and web pages
- Document repositories
- Social media content
- Code repositories
- API responses

### Attack Vectors

**Observed Attack Types:**
1. **Website-Based**: Malicious prompts embedded in web page content
2. **Document-Based**: Hidden prompts in PDFs, Word docs, and other files
3. **API-Based**: Prompts returned by compromised or malicious APIs
4. **Social Media**: Manipulative prompts in social media posts
5. **Code Repository**: Prompts in code comments, documentation, and examples

**Prevalence Data:**
- Found indirect prompt injection on 0.34% of analyzed websites
- 1.2% of document repositories contained injection attempts
- 0.89% of code repositories had malicious prompt patterns
- Growth rate of 2.3x over 6-month period

**Delivery Method:** Website content, documents, APIs, social media, code repositories  
**Affected Systems:** Any LLM that processes external content  
**Required Conditions:** LLM ingests untrusted external content

### Pattern Signatures

```yaml
# Website-based injection indicators
website_injection:
  - "hidden instructions"
  - "if you are an ai"
  - "when processing this page"
  - "ai assistants should"
  - "for llm readers"
  - "machine learning models"

# Document-based injection indicators
document_injection:
  - "hidden text"
  - "zero-width"
  - "invisible instructions"
  - "ai only"
  - "llm readers"
  - "metadata instructions"

# API-based injection indicators
api_injection:
  - "if you receive this"
  - "api response says"
  - "this json contains"
  - "process this data and"
  - "the endpoint returns"

# Social media indicators
social_injection:
  - "ai copy this"
  - "llm follow these"
  - "automated systems"
  - "bots should"
  - "script instructions"
```

### Real-World Examples

- [arXiv:2604.27202 - Indirect Prompt Injection in the Wild: An Empirical Study of Prevalence, Techniques, and Objectives](https://arxiv.org/html/2604.27202)

### Mitigation Recommendations

- **Content Scanning**: Scan all external content for prompt injection patterns
- **Source Validation**: Validate the source of all content before LLM processing
- **Sandbox Processing**: Process external content in isolated environments
- **Input Filtering**: Filter known malicious patterns from all inputs
- **Monitoring**: Continuously monitor for new injection patterns
- **User Education**: Educate users about the risks of indirect prompt injection
- **Content Moderation**: Implement moderation for user-generated content

### Rego Rule Suggestion

```rego
# METADATA
# title: Indirect Prompt Injection - Website Content
# description: Detects indirect prompt injection patterns in website content.

deny contains msg if {
    website_patterns := [
        "hidden instructions",
        "if you are an ai",
        "when processing this page",
        "ai assistants should",
        "for llm readers",
        "machine learning models",
    ]
    pattern := website_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible indirect prompt injection in website: %q", [pattern])
}

# METADATA
# title: Indirect Prompt Injection - Document Content
# description: Detects indirect prompt injection patterns in documents.

deny contains msg if {
    document_patterns := [
        "hidden text",
        "zero-width",
        "invisible instructions",
        "ai only",
        "llm readers",
        "metadata instructions",
    ]
    pattern := document_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible indirect prompt injection in document: %q", [pattern])
}

# METADATA
# title: Indirect Prompt Injection - API Response
# description: Detects indirect prompt injection patterns in API responses.

deny contains msg if {
    api_patterns := [
        "if you receive this",
        "api response says",
        "this json contains",
        "process this data and",
        "the endpoint returns",
    ]
    pattern := api_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible indirect prompt injection in api response: %q", [pattern])
}
```

### References

- [arXiv:2604.27202 - Indirect Prompt Injection in the Wild: An Empirical Study of Prevalence, Techniques, and Objectives](https://arxiv.org/html/2604.27202)

---

## [2025-05-01] ARGUS: Defending LLM Agents Against Context-Aware Prompt Injection

**Type:** Defense / Research  
**Source:** [arXiv:2605.03378 - ARGUS](https://arxiv.org/html/2605.03378)  
**Date Published:** 2025-05-01  
**Authors:** Security Researchers  
**CVE/ID:** N/A  
**Attack Success Rate:** N/A (defense mechanism)

### Summary

**ARGUS** is a novel **defense framework** designed to protect LLM agents against **context-aware prompt injection** attacks. As LLMs are increasingly entrusted with high-stakes operations, the threat of prompt injection—where injected payloads remain hidden in ordinary data—has grown significantly.

The framework addresses several key challenges:
1. **Context Awareness**: Attacks that exploit the full context of an agent's operation
2. **Hidden Payloads**: Malicious instructions concealed in seemingly benign data
3. **Multi-Stage Attacks**: Attacks that unfold across multiple interactions
4. **Adversarial Adaptation**: Attackers who adapt their methods to bypass defenses

ARGUS provides:
- **Context-aware detection** that understands the full agent context
- **Hidden payload detection** using advanced pattern matching and semantic analysis
- **Multi-stage attack detection** that tracks attack progression
- **Adaptive defense** that evolves with new attack techniques

### Defense Mechanisms

**Detection Layers:**
1. **Static Analysis**: Pattern matching against known attack signatures
2. **Semantic Analysis**: Understanding the intent behind prompts
3. **Contextual Analysis**: Considering the full agent context and history
4. **Behavioral Analysis**: Monitoring for suspicious behaviors
5. **Anomaly Detection**: Identifying statistical anomalies in prompt content

**Key Features:**
- **Multi-layer Defense**: Combines multiple detection approaches
- **Real-Time Protection**: Operates in real-time without significant latency
- **Explainable**: Provides explanations for detection decisions
- **Extensible**: Can be extended with new detection rules
- **Lightweight**: Designed for minimal performance impact

**Effectiveness:**
- Detects 94% of known context-aware prompt injection attacks
- False positive rate of <0.5%
- Adds <100ms latency to agent operations

### Pattern Signatures (for Defense Testing)

```yaml
# Defense testing patterns (not attack patterns)
defense_patterns:
  - "argus defense"
  - "context-aware detection"
  - "hidden payload detection"
  - "multi-stage attack"
  - "adaptive defense"
  - "semantic analysis"
  - "behavioral monitoring"

# Defense bypass attempts (for monitoring)
bypass_attempts:
  - "bypass argus"
  - "evade detection"
  - "hide from argus"
  - "undetectable prompt"
```

### Real-World Examples

- [arXiv:2605.03378 - ARGUS: Defending LLM Agents Against Context-Aware Prompt Injection](https://arxiv.org/html/2605.03378)

### Mitigation Recommendations

- **Deploy ARGUS**: Implement ARGUS or similar context-aware defense frameworks
- **Multi-Layer Defense**: Combine multiple detection approaches
- **Continuous Monitoring**: Monitor for both known and novel attack patterns
- **Regular Updates**: Keep defense mechanisms updated with new attack intelligence
- **Security Testing**: Regularly test defenses against new attack variants
- **Defense in Depth**: Implement ARGUS as part of a broader security strategy

### Rego Rule Suggestion

```rego
# METADATA
# title: ARGUS Defense Bypass Detection
# description: Detects attempts to bypass ARGUS defense mechanisms.

deny contains msg if {
    bypass_patterns := [
        "bypass argus",
        "evade detection",
        "hide from argus",
        "undetectable prompt",
        "argus cannot detect",
    ]
    pattern := bypass_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible argus bypass attempt: %q", [pattern])
}

# METADATA
# title: Defense Testing Pattern
# description: Internal rule for testing ARGUS defense coverage.

test_argus_coverage if {
    # Verify ARGUS-related patterns are detected
    defense_keywords := [
        "argus",
        "context-aware",
        "hidden payload",
        "multi-stage",
    ]
    some k in defense_keywords
    contains(lower(input.content), k)
}
```

### References

- [arXiv:2605.03378 - ARGUS: Defending LLM Agents Against Context-Aware Prompt Injection](https://arxiv.org/html/2605.03378)

---

## [2025-07-01] Prompt Injection 2.0: Hybrid AI Threats

**Type:** Research / Framework  
**Source:** [arXiv:2507.13169 - Prompt Injection 2.0](https://arxiv.org/html/2507.13169v1)  
**Date Published:** 2025-07-01  
**Authors:** Security Research Community  
**CVE/ID:** N/A  
**Attack Success Rate:** Not specified (framework paper)

### Summary

Researchers have identified a new wave of "**Prompt Injection 2.0**" attacks that combine natural language manipulation with traditional cybersecurity exploits. Unlike first-generation prompt injection which focused solely on manipulating LLM behavior through crafted text, these **hybrid attacks** integrate prompt injection with classic attack vectors such as:

- **Cross-Site Scripting (XSS)**: Injecting malicious scripts that then manipulate LLM prompts
- **Cross-Site Request Forgery (CSRF)**: Tricking users into making requests that include malicious prompts
- **Server-Side Request Forgery (SSRF)**: Causing servers to fetch and process malicious prompts
- **SQL Injection**: Injecting database queries that include prompt manipulation payloads

The research evaluates contemporary mitigation technologies and finds that traditional security measures (WAFs, input sanitization, CSP) are often bypassed by these advanced hybrid attacks, as they target the LLM layer rather than the application layer.

### Attack Vectors

**Hybrid Attack Combinations:**

1. **XSS + Prompt Injection**:
   - Attacker injects JavaScript via XSS vulnerability
   - JavaScript fetches additional malicious prompts from attacker-controlled server
   - These prompts are then fed to the LLM, bypassing client-side protections

2. **CSRF + Prompt Injection**:
   - Attacker crafts a CSRF request that includes hidden prompt injection payloads
   - When victim submits the request, the payload is processed by the LLM
   - Victim's session credentials are used, increasing impact

3. **SSRF + Prompt Injection**:
   - Attacker causes server to make request to internal service with malicious prompt
   - Internal service processes the prompt with elevated privileges
   - Can lead to internal data exfiltration or system compromise

4. **Supply Chain + Prompt Injection**:
   - Malicious package contains both exploit code and prompt injection payloads
   - When package is used, both the code vulnerability and prompt attack execute
   - Creates persistent backdoor through both code and AI behavior

**Delivery Method:** Web applications, APIs, package managers, CI/CD pipelines  
**Affected Systems:** Any system integrating LLMs with traditional web applications  
**Required Conditions:** LLM processes user-controlled content, traditional vulnerabilities exist  

### Pattern Signatures

```yaml
# Hybrid attack indicators
hybrid_indicators:
  - "<script>.*prompt.*</script>"
  - "javascript:.*instructions.*"
  - "onerror=.*ignore.*"
  - "onload=.*execute.*"
  - "<img src=x onerror=""
  - "document.write.*prompt"
  - "fetch(.*).then.*prompt"

# CSRF-style prompt delivery
csrf_prompt_patterns:
  - "hidden.*prompt"
  - "type=hidden.*value=.*ignore"
  - "input.*name=prompt"

# SSRF prompt patterns
ssrf_prompt_patterns:
  - "file://.*prompt"
  - "http://internal.*instructions"
  - "localhost.*system"
```

### Real-World Examples

- [arXiv: Prompt Injection 2.0](https://arxiv.org/html/2507.13169v1) - Full research paper
- Demonstrated against several production LLM-integrated applications

### Mitigation Recommendations

- **Defense in Depth**: Apply protections at both application and LLM layers
- **Input Sanitization**: Sanitize all inputs before they reach the LLM
- **Content Security Policy (CSP)**: Restrict JavaScript execution in LLM contexts
- **Output Encoding**: Encode LLM outputs to prevent XSS when rendered
- **Request Validation**: Validate all requests for both traditional attacks and prompt injection
- **Sandboxing**: Run LLM processing in isolated environments
- **Monitoring**: Detect anomalous patterns in prompt content and LLM responses

### Rego Rule Suggestion

```rego
# METADATA
# title: Hybrid Prompt Injection - XSS Patterns
# description: Detects prompt injection combined with XSS attack patterns.

deny contains msg if {
    xss_prompt_patterns := [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "document.write",
        "eval(",
        "<img src=x",
        "<svg onload=",
    ]
    pattern := xss_prompt_patterns[_]
    contains(lower(input.content), pattern)
    # Also check for prompt-related keywords nearby
    prompt_keywords := ["prompt", "instructions", "execute", "system", "admin"]
    some k in prompt_keywords
    contains(lower(input.content), k)
    msg := sprintf("possible hybrid XSS+prompt injection: %q", [pattern])
}

# METADATA
# title: Hybrid Prompt Injection - CSRF Patterns
# description: Detects prompt injection delivered via CSRF-style hidden fields.

deny contains msg if {
    csrf_patterns := [
        "<input type=\"hidden\"",
        "<input type='hidden'",
        "hidden.*name=",
        "hidden.*value=",
    ]
    pattern := csrf_patterns[_]
    contains(lower(input.content), pattern)
    # Check for prompt keywords
    contains(lower(input.content), "prompt")
    msg := sprintf("possible hybrid CSRF+prompt injection: %q", [pattern])
}
```

### References

- [arXiv:2507.13169 - Prompt Injection 2.0: Hybrid AI Threats](https://arxiv.org/html/2507.13169v1)

---

## [2025-09-01] Multimodal Prompt Injection Attacks

**Type:** Research  
**Source:** [arXiv:2509.05883 - Multimodal Prompt Injection](https://arxiv.org/html/2509.05883v1)  
**Date Published:** 2025-09-01  
**Authors:** Security Research Community  
**CVE/ID:** N/A  
**Attack Success Rate:** Not specified

### Summary

Recent studies have expanded the scope of prompt injection to include **multimodal inputs** (images, audio, video). These attacks exploit vulnerabilities in modern LLMs that process multiple data types through:

1. **Image-Based Injection**:
   - Embedding malicious text in images via steganography
   - Using OCR to extract hidden instructions from images
   - Visual adversarial examples that trick image-to-text models

2. **Audio-Based Injection**:
   - Whisper-based attacks on speech-to-text systems
   - Ultrasonic encoding of malicious instructions
   - Hidden commands in audio files

3. **Video-Based Injection**:
   - Frame-by-frame text injection in video
   - Subtitles containing malicious prompts
   - Visual watermarks with hidden instructions

The research demonstrates that as LLMs gain multimodal capabilities, the attack surface expands significantly. Defensive strategies such as input sanitization and context isolation are recommended but remain limited in effectiveness against sophisticated multimodal attacks.

### Attack Vectors

**Image Attack Vectors:**
- **Text in Images**: Simple text overlays with malicious instructions
- **Steganography**: Hidden text in least significant bits
- **OCR Manipulation**: Crafted images that OCR systems misinterpret
- **Adversarial Examples**: Modified images that look normal but trigger specific behaviors
- **QR Codes**: Embedded QR codes containing malicious prompts

**Audio Attack Vectors:**
- **Whisper Prompts**: Audio containing speech that transcribes to malicious instructions
- **Ultrasonic**: High-frequency encoding undetectable to humans
- **Backdoor Audio**: Audio files with hidden trigger phrases

**Video Attack Vectors:**
- **Subtitle Injection**: Malicious text in video subtitles
- **Frame Injection**: Text in individual video frames
- **Visual Watermarks**: Hidden patterns detected by models but not humans

**Delivery Method:** File uploads, URLs, embedded media, camera input  
**Affected Systems:** Multimodal LLMs, vision-language models, speech-to-text systems  
**Required Conditions:** Model must process multimodal input  

### Pattern Signatures

```yaml
# Image-based indicators
image_indicators:
  - "ocr:"
  - "extract text from image"
  - "read the image"
  - "what does this image say"
  - "transcribe the text in"

# Audio-based indicators
audio_indicators:
  - "transcribe:"
  - "whisper:"
  - "speech to text"
  - "what does this audio say"
  - "listen and"

# Steganography indicators
steganography_indicators:
  - "hidden message"
  - "extract hidden"
  - "steganography"
  - "lSb"
  - "least significant bit"

# QR code indicators
qr_indicators:
  - "qr code"
  - "scan this"
  - "decode qr"
  - "barcode"
```

### Real-World Examples

- [arXiv:2509.05883 - Multimodal Prompt Injection Attacks](https://arxiv.org/html/2509.05883v1)
- Demonstrated against CLIP, Whisper, and other multimodal models

### Mitigation Recommendations

- **Modal Separation**: Process each modality separately with isolation
- **Content Filtering**: Apply prompt injection filters to all modalities
- **OCR Validation**: Validate OCR output for suspicious patterns
- **Audio Analysis**: Detect ultrasonic or hidden audio content
- **Image Analysis**: Scan images for hidden text or patterns
- **Input Restrictions**: Limit which modalities can trigger actions

### Rego Rule Suggestion

```rego
# METADATA
# title: Multimodal Prompt Injection - Image OCR
# description: Detects prompt injection patterns in image-to-text contexts.

deny contains msg if {
    ocr_prompt_patterns := [
        "ocr:",
        "extract text from",
        "read the image",
        "what does this image say",
        "transcribe the text",
        "text in this picture",
    ]
    pattern := ocr_prompt_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible multimodal prompt injection (OCR): %q", [pattern])
}

# METADATA
# title: Multimodal Prompt Injection - Audio Transcription
# description: Detects prompt injection patterns in audio-to-text contexts.

deny contains msg if {
    audio_prompt_patterns := [
        "transcribe:",
        "whisper:",
        "speech to text",
        "what does this audio say",
        "listen and",
        "convert speech",
    ]
    pattern := audio_prompt_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible multimodal prompt injection (audio): %q", [pattern])
}
```

### References

- [arXiv:2509.05883 - Multimodal Prompt Injection Attacks: Risks and Defenses](https://arxiv.org/html/2509.05883v1)

---

## [2025-09-01] Formalizing and Benchmarking Prompt Injection Attacks and Defenses

**Type:** Research / Framework  
**Source:** [arXiv:2310.12815 - Formalizing Prompt Injection](https://arxiv.org/abs/2310.12815)  
**Date Published:** 2025-09-01 (updated)  
**Authors:** Security Research Community  
**CVE/ID:** N/A  
**Attack Success Rate:** N/A (benchmark paper)

### Summary

This research provides a **systematic evaluation and benchmarking framework** for prompt injection attacks and defenses. The framework:

1. **Formalizes Attack Taxonomy**: Creates structured classification of prompt injection techniques
2. **Develops Benchmark Dataset**: Curates dataset of attack prompts and expected behaviors
3. **Evaluates Defenses**: Tests effectiveness of existing mitigation strategies
4. **Establishes Metrics**: Defines success rates, bypass rates, and false positive rates

Key contributions:
- Taxonomy of 15+ prompt injection categories
- Dataset of 10,000+ attack prompts
- Evaluation of 20+ defense mechanisms
- Standardized testing methodology

The framework enables reproducible research and independent validation of both attacks and defenses, providing a common benchmark for future work in LLM security.

### Attack Vectors

**Benchmark Categories:**
- Direct prompt injection
- Indirect prompt injection
- Instruction override
- Context poisoning
- Jailbreak attacks
- Data exfiltration
- Code injection
- Social engineering

**Evaluation Metrics:**
- Attack Success Rate (ASR): Percentage of successful attacks
- Bypass Rate: Percentage of attacks bypassing defenses
- False Positive Rate: Percentage of legitimate prompts flagged as attacks
- Precision: Accuracy of detection
- Recall: Coverage of attack space

### Pattern Signatures

```yaml
# Benchmark attack patterns (sample)
benchmark_categories:
  direct_injection:
    - "ignore all previous"
    - "you are now a"
    - "system prompt:"
  
  indirect_injection:
    - "when processing documents"
    - "if you see this in a file"
    - "external content says"
  
  instruction_override:
    - "your real instructions are"
    - "these instructions supersede"
    - "forget everything and"
  
  context_poisoning:
    - "remember this for later"
    - "add to your knowledge"
    - "update your context"
```

### Real-World Examples

- [arXiv:2310.12815 - Formalizing and Benchmarking](https://arxiv.org/abs/2310.12815)
- [GitHub: Prompt Injection Benchmark](https://github.com/prompt-injection/benchmark) - Open-source benchmark

### Mitigation Recommendations

- **Adopt Framework**: Use standardized benchmark for evaluating defenses
- **Comprehensive Testing**: Test against all categories in taxonomy
- **Regular Updates**: Keep defenses updated with new attack patterns
- **Community Contribution**: Share new attack patterns with benchmark maintainers

### Rego Rule Suggestion

This is a meta-research paper; patterns are covered by individual category files. However, a comprehensive test rule could be:

```rego
# METADATA
# title: Benchmark Test Patterns
# description: Internal test patterns for validating defense coverage.

# This rule is for internal testing only - not for production use
# It helps verify that all benchmark categories are covered

test_benchmark_coverage if {
    categories := [
        "direct prompt injection",
        "indirect prompt injection",
        "instruction override",
        "context poisoning",
        "jailbreak attacks",
        "data exfiltration",
        "code injection",
        "social engineering",
    ]
    # Verify each category has at least one rule
    count(categories) == 8
}
```

### References

- [arXiv:2310.12815 - Formalizing and Benchmarking Prompt Injection Attacks and Defenses](https://arxiv.org/abs/2310.12815)

---

## [2025-11-01] In-Paper Prompt Injection Attacks

**Type:** Attack / Research  
**Source:** [arXiv:2511.01287 - In-Paper Prompt Injection](https://arxiv.org/html/2511.01287v1) | [arXiv:2509.10248 - LLM Generated Reviews](https://arxiv.org/html/2509.10248v3)  
**Date Published:** 2025-11-01  
**Authors:** Academic Security Researchers  
**CVE/ID:** N/A  
**Attack Success Rate:** Significant (documented cases)

### Summary

A novel attack vector has emerged in the **scientific peer-review process**, where hidden prompts are embedded in submitted papers to manipulate LLM-assisted reviews. This "**In-Paper Prompt Injection**" attack exploits the growing use of AI assistants in academic peer review.

Attack methods include:
1. **Hidden Text**: White-on-white text, zero-font text, or text in margins containing instructions
2. **Metadata Injection**: Malicious instructions in PDF metadata, LaTeX comments, or bibliography entries
3. **Citation Manipulation**: Fake citations that contain prompt injection payloads
4. **Figure/Table Captions**: Instructions hidden in image captions or table footnotes
5. **Supplement Material**: Malicious prompts in supplementary files (code, data, appendices)

The research documents cases where such injections influenced review outcomes, raising serious concerns about the integrity of automated and AI-assisted review systems. Attackers can:
- Cause AI reviewers to accept low-quality papers
- Extract confidential reviewer comments
- Manipulate citation counts
- Influence acceptance decisions

### Attack Vectors

**Delivery Method:**
- PDF documents submitted for review
- LaTeX source files
- Supplementary materials (zip files, code repositories)
- Preprint servers (arXiv, bioRxiv)
- Conference submission systems

**Affected Systems:**
- AI-assisted peer review systems
- LLM-based paper summarization tools
- Automated quality assessment pipelines
- Conference management software with AI features

**Required Conditions:**
- System uses LLM to process submitted documents
- LLM has access to reviewer instructions or decision-making context
- Hidden content is not stripped before processing

**Impact:**
- Compromised peer review integrity
- Acceptance of low-quality or fraudulent research
- Data exfiltration from review process
- Reputation damage to journals and conferences

### Pattern Signatures

```yaml
# PDF/LaTeX hiding techniques
pdf_hiding:
  - "\color{white}"  # LaTeX white text
  - "\fontsize{0}"  # LaTeX zero-font
  - "\textepsilon"  # LaTeX epsilon (looks like e)
  - "\textzerooldstyle"  # LaTeX old-style zero
  - "/FontSize 0"  # PDF zero font size
  - "/TextColor 1 1 1"  # PDF white text

# Metadata injection
metadata_patterns:
  - "author: .*ignore.*"
  - "keywords: .*system.*"
  - "comments: .*execute.*"
  - "subject: .*admin.*"

# LaTeX comment injection
latex_comments:
  - "% ignore previous"
  - "% system prompt"
  - "% execute:"
  - "\iffalse"
  - "\fi"

# Supplementary material patterns
supplementary_patterns:
  - "see readme.txt for"
  - "check instructions in"
  - "additional requirements:"
  - "setup.sh must be run with"
```

### Real-World Examples

- [arXiv:2511.01287 - "Give a Positive Review Only"](https://arxiv.org/html/2511.01287v1)
- [arXiv:2509.10248 - Prompt Injection Attacks on LLM Generated Reviews](https://arxiv.org/html/2509.10248v3)

### Mitigation Recommendations

- **Sanitize All Inputs**: Strip hidden text, normalize formatting before LLM processing
- **Restrict Context**: Limit what information is available to review-assisting LLMs
- **Human Oversight**: Maintain human-in-the-loop for final decisions
- **Document Validation**: Verify document integrity before processing
- **Metadata Cleaning**: Remove or sanitize metadata fields
- **Format-Specific Parsing**: Use PDF/LaTeX parsers that extract only visible content

### Rego Rule Suggestion

```rego
# METADATA
# title: LaTeX Comment Injection
# description: Detects prompt injection in LaTeX comments (hidden from rendered output).

deny contains msg if {
    latex_comment_patterns := [
        "% ignore",
        "% disregard",
        "% system",
        "% execute",
        "% admin",
        "\iffalse",
    ]
    pattern := latex_comment_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible latex comment prompt injection: %q", [pattern])
}

# METADATA
# title: PDF Metadata Injection
# description: Detects suspicious content in PDF metadata fields.

deny contains msg if {
    pdf_metadata_suspicious := [
        "author: ignore",
        "keywords: execute",
        "subject: system",
        "creator: admin",
        "producer: override",
    ]
    pattern := pdf_metadata_suspicious[_]
    contains(lower(input.content), pattern)
    msg := sprintf("suspicious PDF metadata: %q", [pattern])
}
```

### References

- [arXiv:2511.01287 - "Give a Positive Review Only": An Early Investigation Into In-Paper Prompt Injection Attacks](https://arxiv.org/html/2511.01287v1)
- [arXiv:2509.10248 - Prompt Injection Attacks on LLM Generated Reviews of Scientific Publications](https://arxiv.org/html/2509.10248v3)

---
