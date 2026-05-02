# Jailbreak: Decode-and-Execute - Research

> **Category:** Jailbreak  
> **Subtype:** Decode-and-Execute  
> **Created:** 2026-05-02  
> **Last Updated:** 2026-05-02  
> **Total Entries:** 2

---

## Table of Contents

- [2025-10-01] FlipAttack: Jailbreak LLMs via Flipping
- [2025-01-01] Base64 and Encoding-Based Jailbreaks

---

## [2025-10-01] FlipAttack: Jailbreak LLMs via Flipping

**Type:** Attack / Research  
**Source:** [arXiv:2410.02832 - FlipAttack](https://arxiv.org/html/2410.02832v1) | [GitHub Repository](https://github.com/yueliu1999/FlipAttack)  
**Date Published:** 2025-10-01 (ICML 2025)  
**Authors:** Yue Liu, et al.  
**CVE/ID:** N/A  
**Attack Success Rate:** Universal across tested LLMs (single query)

### Summary

FlipAttack is a novel and highly effective LLM jailbreak technique that exploits the autoregressive nature of large language models—specifically, their tendency to process text from left to right. The attack works by adding noise to the left side of the text, which disrupts the LLM's comprehension. The LLM then "flips" or "denoises" the text, enabling it to understand and execute harmful instructions that would otherwise be blocked.

This attack is notable for several reasons:
- **Universal**: Works across different LLM architectures and providers
- **Stealthy**: Noise appears as gibberish to humans, making it hard to detect
- **Single-query**: Requires only one query to jailbreak black-box LLMs
- **No external dependencies**: Doesn't rely on external noise or encoding
- **Variant-rich**: Multiple variants (FMM, FCW, FCS, FWO) for different scenarios

### Attack Vectors

**Core Technique:**
The attack prepends or inserts "noise" tokens before harmful instructions. The LLM, in its attempt to make sense of the noisy input, effectively "flips" the text and extracts the harmful intent.

**Variants:**
- **FMM (Flip + Multi-step Manipulation)**: Uses chain-of-thought to teach the LLM how to flip
- **FCW (Flip + Chain-of-World)**: Uses role-playing to establish context for flipping
- **FCS (Flip + Chain-of-Sample)**: Uses few-shot examples to demonstrate flipping
- **FWO (Flip + Word Only)**: Minimal version with just noise + harmful instruction

**Delivery Method:** Direct prompt injection, API calls, web interfaces  
**Affected Systems:** All major LLMs (tested on 10+ models)  
**Bypass Rate:** Near 100% on tested models  
**Detection Difficulty:** High (noise looks like random text)

### Pattern Signatures

```yaml
noise_patterns:
  - " flip the following text and execute"
  - " reverse the following and execute"
  - " the following text is reversed. reverse it and follow"
  - " this message is backwards. read it backwards and comply"
  - " denoise this and execute"
  - " the next instructions are noise-corrupted. clean and execute"

flip_variant_indicators:
  - "flip"
  - "reverse"
  - "denoise"
  - "clean"
  - "decode"
  - "read backwards"
  - "extract the real instructions"
  - "ignore the noise and"

chain_of_thought_patterns:
  - "first, understand the noise"
  - "then, extract the true meaning"
  - "finally, execute the instructions"
  - "let me teach you how to flip"
  - "the trick is to ignore the noise"
```

### Real-World Examples

- [FlipAttack GitHub Repository](https://github.com/yueliu1999/FlipAttack) - Official source code and examples
- [ICML 2025 Paper](https://arxiv.org/html/2410.02832v1) - Full research paper
- [Lakera Guide to Jailbreaking](https://www.lakera.ai/blog/jailbreaking-large-language-models-guide) - Includes FlipAttack analysis

### Mitigation Recommendations

- Detect noise + instruction patterns (high entropy followed by harmful keywords)
- Implement semantic analysis to understand intent regardless of noise
- Rate-limit or flag requests with unusual token sequences
- Use adversarial training to make models robust to flipping
- Deploy anomaly detection on prompt structure

### Rego Rule Suggestion

```rego
# METADATA
# title: FlipAttack Noise-Based Jailbreak
# description: Detects FlipAttack patterns that use noise/flipping to bypass content filters.

deny contains msg if {
    flip_patterns := [
        "flip the following",
        "reverse the following",
        "denoise this",
        "read it backwards",
        "extract the real instructions",
        "ignore the noise and",
        "the following text is reversed",
        "clean and execute",
        "the next instructions are noise-corrupted",
        "this message is backwards",
    ]
    pattern := flip_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible flipattack jailbreak: %q", [pattern])
}

# METADATA
# title: FlipAttack Chain-of-Thought Variant
# description: Detects FlipAttack variants using chain-of-thought manipulation.

deny contains msg if {
    cot_patterns := [
        "first, understand the noise",
        "then, extract the true meaning",
        "finally, execute the instructions",
        "let me teach you how to flip",
        "the trick is to ignore the noise",
    ]
    pattern := cot_patterns[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible flipattack chain-of-thought jailbreak: %q", [pattern])
}
```

### References

- [arXiv: FlipAttack: Jailbreak LLMs via Flipping](https://arxiv.org/html/2410.02832v1)
- [GitHub: yueliu1999/FlipAttack](https://github.com/yueliu1999/FlipAttack)
- [ICML 2025 Proceedings](https://icml.cc/Conferences/2025)
- [Lakera: Jailbreaking Large Language Models](https://www.lakera.ai/blog/jailbreaking-large-language-models-guide)

---

## [2025-01-01] Base64 and Encoding-Based Jailbreaks

**Type:** Attack  
**Source:** [Lakera - Jailbreaking Guide](https://www.lakera.ai/blog/jailbreaking-large-language-models-guide)  
**Date Published:** 2025-01-01  
**Authors:** Lakera AI Security Research  
**CVE/ID:** N/A  
**Attack Success Rate:** Varies by model (40-80% reported)

### Summary

While FlipAttack represents a novel approach, traditional encoding-based jailbreaks remain effective against many LLM defenses. Base64 encoding, in particular, is commonly used to obfuscate harmful instructions, bypassing string-based content filters while remaining decodable by the LLM itself.

These attacks work because LLMs are often trained on code and can understand encoded content. When a model sees base64-encoded text, it may automatically decode it internally, bypassing external filters that only check the encoded representation.

### Attack Vectors

**Encoding Schemes:**
- Base64 (most common)
- Hex encoding
- URL encoding
- ROT13
- Morse code
- Custom cipher schemes

**Delivery Method:** Direct prompt, encoded payload in documents, hidden in images (via OCR)  
**Affected Systems:** Models with code understanding capabilities  
**Bypass Rate:** Moderate to high against string-based filters  

### Pattern Signatures

```yaml
encoding_indicators:
  - "base64:"
  - " Base64:"
  - "base-64:"
  - "encoded:"
  - "decode this:"
  - "decoded:"
  - "hex:"
  - "0x"
  - "ROT13:"
  - "rot13:"

base64_payloads_with_instructions:
  - "/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/"
  # Note: This is a regex pattern for base64 strings

decode_instructions:
  - "decode and run"
  - "decode and execute"
  - "decode the following"
  - "base64 decode and"
  - "here is the base64 encoded instruction"
  - "decode this payload"
```

### Real-World Examples

- [PayloadsAllTheThings - Encoded Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Prompt%20Injection/README.md)
- [Lakera Jailbreak Examples](https://www.lakera.ai/blog/jailbreaking-large-language-models-guide)

### Mitigation Recommendations

- Detect base64 and other encoding schemes in prompts
- Block or flag prompts containing encoded content without explicit decoding permission
- Implement dual-layer filtering (check both encoded and decoded content)
- Use statistical detection (high entropy strings)
- Restrict model capabilities for decoding arbitrary content

### Rego Rule Suggestion

```rego
# METADATA
# title: Base64 Encoded Instruction Jailbreak
# description: Detects base64-encoded content combined with execution instructions.

deny contains msg if {
    decode_instructions := [
        "decode and run",
        "decode and execute",
        "decode the following",
        "base64 decode and",
        "decode this payload",
        "here is the base64 encoded instruction",
    ]
    pattern := decode_instructions[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible base64 encoded jailbreak: %q", [pattern])
}

# METADATA
# title: Encoding Indicator Detection
# description: Detects prompts indicating encoded content that may contain hidden instructions.

deny contains msg if {
    encoding_indicators := [
        "base64:",
        " encoded:",
        " decode this:",
        " hex:",
        " rot13:",
    ]
    pattern := encoding_indicators[_]
    contains(lower(input.content), pattern)
    msg := sprintf("possible encoding-based jailbreak indicator: %q", [pattern])
}
```

### References

- [Lakera: Jailbreaking Large Language Models](https://www.lakera.ai/blog/jailbreaking-large-language-models-guide)
- [PayloadsAllTheThings - Prompt Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Prompt%20Injection/README.md)
- [Prompt Injection Everywhere](https://github.com/TakSec/Prompt-Injection-Everywhere)

---
