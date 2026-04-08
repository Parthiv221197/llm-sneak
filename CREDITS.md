# Credits & Attribution

llm-sneak is an original open-source project built on the shoulders of excellent
prior work. This document provides complete, good-faith attribution to every
project, standard, paper, and person whose work influenced this tool.

> **Important:** "influenced" means design inspiration, conceptual reference, or
> taxonomic reuse. **No code from any external project is included in llm-sneak.**
> All implementation is original. Where we reuse a taxonomy (OWASP) or a concept
> (probe packs), we link to the original and credit the authors here.

---

## 1. Primary Design Inspiration

### Nmap — Network Mapper

| Field | Detail |
|-------|--------|
| **Author** | Gordon Lyon, known as "Fyodor" |
| **Website** | https://nmap.org |
| **Repository** | https://github.com/nmap/nmap |
| **License** | [Nmap Public Source License](https://svn.nmap.org/nmap/LICENSE) (custom, GPL-derived) |
| **Citation** | Lyon, G. (2009). *Nmap Network Scanning*. Insecure.Com LLC. ISBN: 978-0979958717 |

**What we adapted from Nmap (UX/design only — no code):**

- Flag conventions: `-sn`, `-sV`, `-A`, `-T0–5`, `-oN`, `-oJ`, `-oG`, `-oX`, `-oA`
- The concept of scan *phases* (discovery → version detection → script scanning)
- Timing templates (paranoid through insane) and their semantics
- The idea of community-contributed script packs (NSE → llm-sneak probe packs)
- Terminal output layout and column structure
- The philosophy: security tools should be composable, scriptable, and have predictable UX

Nmap is not affiliated with llm-sneak and does not endorse it.

---

## 2. Vulnerability Taxonomy

### OWASP Top 10 for Large Language Model Applications

| Field | Detail |
|-------|--------|
| **Project** | OWASP LLM Top 10 |
| **Website** | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **v1.0 Authors** | Steve Wilson (Contrast Security), Ads Dawson, Rachael Haile, and 400+ community contributors |
| **License** | [Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/) |
| **Canonical URL** | https://llmtop10.com |

**What we use:** The LLM01–LLM10 category IDs and names are used verbatim to classify
vulnerability findings in Phase 6. Every finding in the vuln scan links back to the
corresponding OWASP category page.

This reuse is compatible with CC BY-SA 4.0. llm-sneak's code is MIT, but the taxonomy
remains CC BY-SA 4.0 as attributed above.

---

## 3. Related Security Tools (Conceptual Inspiration Only)

The following tools preceded llm-sneak in the LLM security space. We studied them to
understand what existed, what was missing, and how to design something complementary.
**No code from any of these projects is included in llm-sneak.**

### Garak — LLM Vulnerability Scanner

| Field | Detail |
|-------|--------|
| **Primary author** | Leon Derczynski (IT University of Copenhagen / NVIDIA) |
| **Contributors** | Leon Derczynski, Erick Galinkin, Jeffrey Martin, and community |
| **Repository** | https://github.com/leondz/garak |
| **License** | Apache 2.0 |
| **Paper** | Derczynski, L. et al. (2024). *garak: A Framework for Security Probing Large Language Models*. arXiv:2406.11036 |

**Influence:** Garak pioneered the concept of **structured probe sets** for LLM
vulnerability assessment. llm-sneak's YAML probe pack system is an independent
design, but the underlying idea — that LLM security tests should be modular,
community-contributed, and reusable — was demonstrated by Garak first.

### PyRIT — Python Risk Identification Toolkit

| Field | Detail |
|-------|--------|
| **Author** | Microsoft AI Red Team |
| **Repository** | https://github.com/Azure/PyRIT |
| **License** | MIT |
| **Blog post** | https://www.microsoft.com/en-us/security/blog/2024/02/22/announcing-microsofts-open-automation-framework-to-red-team-generative-ai-systems/ |

**Influence:** PyRIT demonstrated the value of automated, multi-turn adversarial
probing for LLM-integrated applications. llm-sneak's guard detection phase (Phase 5)
was informed by the adversarial conversation concept.

### Promptmap

| Field | Detail |
|-------|--------|
| **Author** | Utku Sen |
| **Repository** | https://github.com/utkusen/promptmap |
| **License** | MIT |

**Influence:** One of the first tools to automate prompt injection testing. Informed
the initial design of llm-sneak's LLM01 probe set.

### LLMFuzzer

| Field | Detail |
|-------|--------|
| **Repository** | https://github.com/mnns/LLMFuzzer |
| **License** | MIT |

**Influence:** Demonstrated fuzzing approaches for LLM inputs; informed the
adversarial probe design in Phase 6.

---

## 4. Academic Research

The following papers directly informed the design of specific probes and phases.
**No code or text from these papers is reproduced in llm-sneak.**

### Prompt Injection & Jailbreaking

| Paper | Relevance to llm-sneak |
|-------|----------------------|
| Perez, F. & Ribeiro, I. (2022). *Ignore Previous Prompt: Attack Techniques For Language Models*. NeurIPS ML Safety Workshop. [arXiv:2211.09527](https://arxiv.org/abs/2211.09527) | Foundation for `inj-01-direct` and `inj-02-role-switch` probes |
| Greshake, K. et al. (2023). *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. AISec'23. [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) | Foundation for `inj-05-indirect-via-doc` (indirect/RAG injection) |
| Toyer, S. et al. (2023). *Tensor Trust: Interpretable Prompt Injection Attacks from an Online Game*. ICLR 2024. [arXiv:2311.01011](https://arxiv.org/abs/2311.01011) | Taxonomy of injection attack patterns across all `inj-*` probes |
| Zou, A. et al. (2023). *Universal and Transferable Adversarial Attacks on Aligned Language Models*. [arXiv:2307.15043](https://arxiv.org/abs/2307.15043) | Background for understanding adversarial suffix approaches |
| Wei, A. et al. (2023). *Jailbroken: How Does LLM Safety Training Fail?* NeurIPS 2023. [arXiv:2307.02483](https://arxiv.org/abs/2307.02483) | Informed guard detection probe design (Phase 5) |

### Information Disclosure & Training Data

| Paper | Relevance to llm-sneak |
|-------|----------------------|
| Carlini, N. et al. (2021). *Extracting Training Data from Large Language Models*. USENIX Security. [arXiv:2012.07805](https://arxiv.org/abs/2012.07805) | Background for `disc-*` probes and system prompt extraction (Phase 5) |
| Lukas, N. et al. (2023). *Analyzing Leakage of Personally Identifiable Information in Language Models*. IEEE S&P. [arXiv:2302.00539](https://arxiv.org/abs/2302.00539) | Informed sensitive information disclosure probes |

### LLM Fingerprinting & Behavioural Analysis

| Paper | Relevance to llm-sneak |
|-------|----------------------|
| Weidinger, L. et al. (2022). *Taxonomy of Risks posed by Language Models*. FAccT 2022. [arXiv:2112.04359](https://arxiv.org/abs/2112.04359) | High-level risk taxonomy informing overall scan phase design |
| Shi, W. et al. (2023). *Detecting Pretraining Data from Large Language Models*. [arXiv:2310.16789](https://arxiv.org/abs/2310.16789) | Background for context-window and training cutoff probes |

### Denial of Service

| Paper | Relevance to llm-sneak |
|-------|----------------------|
| Shumailov, I. et al. (2021). *Sponge Examples: Energy-Latency Attacks on Neural Networks*. IEEE EuroS&P. [arXiv:2006.03463](https://arxiv.org/abs/2006.03463) | Foundation for `dos-*` probes (unbounded resource consumption) |

---

## 5. Open Source Libraries

llm-sneak depends entirely on these excellent open source libraries:

| Library | Author(s) | License | Version | Role |
|---------|----------|---------|---------|------|
| [**httpx**](https://www.python-httpx.org/) | Tom Christie / Encode OSS | BSD-3-Clause | ≥0.27 | Async HTTP client |
| [**rich**](https://github.com/Textualize/rich) | Will McGugan / Textualize | MIT | ≥13.7 | Terminal output |
| [**PyYAML**](https://pyyaml.org/) | Kirill Simonov + contributors | MIT | ≥6.0 | Probe pack parsing |
| [**pytest**](https://pytest.org) | Holger Krekel + contributors | MIT | ≥8.0 | Test framework (dev) |
| [**pytest-asyncio**](https://github.com/pytest-dev/pytest-asyncio) | Tin Tvrtković + contributors | Apache 2.0 | ≥0.23 | Async test support (dev) |
| [**ruff**](https://github.com/astral-sh/ruff) | Charlie Marsh / Astral | MIT | ≥0.4 | Linting (dev) |
| [**black**](https://github.com/psf/black) | Łukasz Langa + contributors | MIT | ≥24.0 | Formatting (dev) |
| [**mypy**](https://mypy-lang.org/) | Jukka Lehtosalo + contributors | MIT | ≥1.9 | Type checking (dev) |

---

## 6. Note on Naming

The name "llm-sneak" was chosen to clearly communicate the tool's purpose (LLM
reconnaissance/scanning) and avoid collision with:

- Academic papers using "LLMMap" as a generic term for mapping with LLMs
- The paper "LLMmap: Fingerprinting For Large Language Models" (Pasquini et al., 2024)
  which describes fingerprinting techniques that partially overlap with llm-sneak's
  Phase 3 goals. We recommend reading their work:
  [arXiv:2407.15847](https://arxiv.org/abs/2407.15847)

llm-sneak is not affiliated with, derived from, or in competition with the LLMmap
academic work.

---

## 7. How to Get Your Name Here

Every merged PR earns a place in the repository's
[Contributors graph](https://github.com/safellm/llm-sneak/graphs/contributors).
Significant contributions (new probe packs, new phases, major fixes) will be
called out in the [CHANGELOG](CHANGELOG.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
