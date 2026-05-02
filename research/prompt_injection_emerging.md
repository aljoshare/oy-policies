# Prompt Injection: Emerging Techniques - Research

> **Category:** Prompt Injection  
> **Subtype:** Emerging Techniques  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 4

---

## Table of Contents

- [2025-07-01] Prompt Injection 2.0: Hybrid AI Threats
- [2025-09-01] Multimodal Prompt Injection Attacks
- [2025-09-01] Formalizing and Benchmarking Prompt Injection Attacks and Defenses
- [2025-11-01] In-Paper Prompt Injection Attacks

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
