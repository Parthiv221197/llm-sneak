# Security Policy

## Scope of llm-sneak

llm-sneak is a **defensive security research tool** for assessing LLM infrastructure
you own or are authorised to test. Its vulnerability probes detect *whether* security
properties exist — they do not exfiltrate harmful data or cause real-world harm.

## Responsible Use

By using llm-sneak you agree to:
1. Only scan systems you own or have explicit written authorisation to test
2. Disclose discovered vulnerabilities in third-party systems to their owners
   responsibly before publishing

## Reporting a Vulnerability in llm-sneak Itself

If you find a security issue in llm-sneak's code (e.g. code execution via a
malicious probe pack YAML, output path traversal):

1. **Do NOT open a public GitHub issue**
2. Email **security@llm-sneak.dev** with:
   - Description and steps to reproduce
   - Potential impact
   - Your suggested fix (optional)
3. We will acknowledge within **48 hours** and patch critical issues within **14 days**
4. We will credit you in the release notes (unless you prefer anonymity)

## Supported Versions

Only the latest release on `main` is actively maintained.

## Safe Harbour

We will not pursue legal action against researchers who discover and report
vulnerabilities in good faith, do not access data beyond what's needed to
demonstrate the issue, and give us reasonable time to patch before disclosure.
