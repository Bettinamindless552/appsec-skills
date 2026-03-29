<p align="center">
  <img src="./assets/eresus-banner.svg" alt="Eresus Security Banner" width="100%" />
</p>

<h1 align="center">Eresus AppSec Skills</h1>

<p align="center">
  Production-oriented AI security skills for static analysis, threat modeling, remediation, security review, and serialization-focused audits.
</p>

<p align="center">
  <a href="https://github.com/organizations/EresusSecurity/">EresusSecurity GitHub</a>
</p>

---

## Overview

`eresus-sast-scanner` is the core skill in the Eresus Security AppSec suite for AI coding agents such as OpenAI Codex and Claude Code. It is designed to help agents review source code with a structured, evidence-first security workflow instead of loose pattern matching.

The suite focuses on practical application security work:

- full-repository or targeted SAST scanning
- threat modeling for new features and services
- PR and diff-focused security review
- remediation of confirmed findings
- deep analysis of serialization and deserialization attack surface

Supported language families include **Java, Python, JavaScript/TypeScript, PHP, and .NET**.

## Included Skills

| Skill | Primary Use |
|------|-------------|
| `eresus-sast-scanner` | Full-repo or targeted SAST scan across 34 vulnerability classes |
| `eresus-remediator` | Patch confirmed findings with root-cause-focused fixes |
| `eresus-pr-security-review` | Review PRs and changed files for newly introduced security issues |
| `eresus-threat-modeler` | Model attack paths, trust boundaries, and high-risk workflows before scanning or implementation |
| `eresus-serialization-review` | Deep review of deserialization, parser abuse, object mapping, and state-transfer risks |

## Why This Suite

This suite is built around a simple principle: security findings should be tied to a believable exploit path.

Instead of stopping at suspicious strings, the core scanner pushes the agent to:

1. identify attacker-controlled sources
2. trace tainted data through the codebase
3. verify that it reaches a dangerous sink
4. challenge the finding with a Judge step to reduce false positives
5. produce actionable remediation guidance

That makes it useful not only for vulnerability hunting, but also for patching, design review, and PR gating.

## Quick Start

Recommended repository name: `eresus-appsec-skills`

### Install From Git

```bash
# Claude Code
git clone https://github.com/EresusSecurity/eresus-appsec-skills.git
cp -r eresus-appsec-skills/skills/eresus-sast-scanner/ ~/.claude/skills/
cp -r eresus-appsec-skills/skills/eresus-remediator/ ~/.claude/skills/
cp -r eresus-appsec-skills/skills/eresus-pr-security-review/ ~/.claude/skills/
cp -r eresus-appsec-skills/skills/eresus-threat-modeler/ ~/.claude/skills/
cp -r eresus-appsec-skills/skills/eresus-serialization-review/ ~/.claude/skills/

# OpenAI Codex
git clone https://github.com/EresusSecurity/eresus-appsec-skills.git
cp -r eresus-appsec-skills/skills/eresus-sast-scanner/ ~/.codex/skills/
cp -r eresus-appsec-skills/skills/eresus-remediator/ ~/.codex/skills/
cp -r eresus-appsec-skills/skills/eresus-pr-security-review/ ~/.codex/skills/
cp -r eresus-appsec-skills/skills/eresus-threat-modeler/ ~/.codex/skills/
cp -r eresus-appsec-skills/skills/eresus-serialization-review/ ~/.codex/skills/
```

### Manual Install

Copy the skill directories you want into your agent's skills folder:

```bash
# Claude Code
cp -r skills/eresus-sast-scanner/ ~/.claude/skills/
cp -r skills/eresus-remediator/ ~/.claude/skills/
cp -r skills/eresus-pr-security-review/ ~/.claude/skills/
cp -r skills/eresus-threat-modeler/ ~/.claude/skills/
cp -r skills/eresus-serialization-review/ ~/.claude/skills/

# OpenAI Codex
cp -r skills/eresus-sast-scanner/ ~/.codex/skills/
cp -r skills/eresus-remediator/ ~/.codex/skills/
cp -r skills/eresus-pr-security-review/ ~/.codex/skills/
cp -r skills/eresus-threat-modeler/ ~/.codex/skills/
cp -r skills/eresus-serialization-review/ ~/.codex/skills/
```

## Recommended Usage

| Goal | Recommended Skill |
|------|-------------------|
| Audit a repository for security bugs | `eresus-sast-scanner` |
| Review a pull request or changed files | `eresus-pr-security-review` |
| Patch a confirmed vulnerability | `eresus-remediator` |
| Threat model a new feature or service | `eresus-threat-modeler` |
| Audit Jackson, Fastjson, YAML, XML, cookies, sessions, or queue payloads | `eresus-serialization-review` |

## Core Scanner Workflow

The main scanner skill follows a structured six-step process:

1. **Understand scope**  
   Determine whether the target is a file, module, endpoint, service, or full repository.

2. **Load relevant knowledge**  
   Pull in the vulnerability knowledge files relevant to the language, framework, and attack surface.

3. **Trace source-to-sink flow**  
   Track attacker-controlled input through transformations into sensitive operations.

4. **Check business logic and authorization**  
   Look beyond injection bugs for IDOR, privilege issues, race conditions, token misuse, and trust-boundary problems.

5. **Judge every candidate finding**  
   Re-check reachability, sanitization, framework protections, and exploitability before reporting.

6. **Report actionable findings**  
   Output precise file locations, impact, evidence, and fix guidance.

## Vulnerability Coverage

The core scanner includes built-in knowledge for **34 vulnerability classes**.

### Injection

| File | Coverage |
|------|----------|
| `sql_injection.md` | SQL Injection |
| `xss.md` | Cross-Site Scripting |
| `ssti.md` | Server-Side Template Injection |
| `nosql_injection.md` | NoSQL Injection |
| `graphql_injection.md` | GraphQL Injection / Introspection Abuse |
| `xxe.md` | XML External Entity |
| `rce.md` | Remote Code Execution / Command Injection |
| `expression_language_injection.md` | Expression Language Injection |

### Access Control And Auth

| File | Coverage |
|------|----------|
| `idor.md` | Insecure Direct Object Reference |
| `privilege_escalation.md` | Privilege Escalation |
| `authentication_jwt.md` | JWT Weaknesses and Authentication Flaws |
| `default_credentials.md` | Hardcoded or Default Credentials |
| `brute_force.md` | Brute Force and Missing Rate Limiting |
| `business_logic.md` | Business Logic Flaws |
| `http_method_tamper.md` | HTTP Method Tampering |
| `verification_code_abuse.md` | Verification Code Abuse |
| `session_fixation.md` | Session Fixation |

### Data Exposure And Crypto

| File | Coverage |
|------|----------|
| `weak_crypto_hash.md` | Weak Cryptography, Weak Hashing, Weak Randomness |
| `information_disclosure.md` | Sensitive Information Disclosure |
| `insecure_cookie.md` | Insecure Cookie Flags |
| `trust_boundary.md` | Trust Boundary Violations |

### Server-Side And Parser Risk

| File | Coverage |
|------|----------|
| `ssrf.md` | Server-Side Request Forgery |
| `path_traversal_lfi_rfi.md` | Path Traversal, LFI, RFI |
| `insecure_deserialization.md` | Insecure Deserialization |
| `arbitrary_file_upload.md` | Arbitrary File Upload |
| `jndi_injection.md` | JNDI Injection |
| `race_conditions.md` | Race Conditions and TOCTOU |

### Protocol And Infrastructure

| File | Coverage |
|------|----------|
| `csrf.md` | Cross-Site Request Forgery |
| `open_redirect.md` | Open Redirect |
| `smuggling_desync.md` | HTTP Request Smuggling / Desync |
| `denial_of_service.md` | Resource Exhaustion and Denial of Service |
| `cve_patterns.md` | High-Risk CVE-Style Code Patterns |

### Language And Platform

| File | Coverage |
|------|----------|
| `php_security.md` | PHP-Specific Security Risks |
| `mobile_security.md` | Android and iOS Security Risks |

## Professional Usage Patterns

- Use `eresus-threat-modeler` before auditing large features so the scan starts from the right trust boundaries.
- Use `eresus-pr-security-review` during code review to focus on newly introduced attack surface instead of re-auditing the whole repository.
- Use `eresus-remediator` after a confirmed finding to drive minimal, production-safe patches.
- Use `eresus-serialization-review` when the system relies on session blobs, queues, import/export features, or dynamic parser configuration.
- Run more than one scan round for large codebases when you want better recall and more stable reporting.

## Benchmarks

> Benchmark numbers are reference values and may vary by model configuration, prompt strategy, and available context.

### Multi-Agent Plus Skill — Claude Opus 4.6 High — 2026-03-27

4 Java benchmark projects were scanned in parallel using 4 agents with the full scanner workflow and Judge verification enabled.

| Project | Recall | Precision | F1 | TP | FN | FP |
|---------|:------:|:---------:|:--:|:--:|:--:|:--:|
| JavaSecLab | 1.000 | 0.958 | 0.979 | 23 | 0 | 1 |
| SecExample | 1.000 | 1.000 | 1.000 | 9 | 0 | 0 |
| VulnerableApp | 1.000 | 1.000 | 1.000 | 10 | 0 | 0 |
| verademo | 1.000 | 1.000 | 1.000 | 14 | 0 | 0 |
| **Global** | **1.000** | **0.982** | **0.991** | **56** | **0** | **1** |

### Multi-Agent Plus Skill — GPT-5.4 High — 2026-03-27

| Project | Recall | Precision | F1 | TP | FN | FP |
|---------|:------:|:---------:|:--:|:--:|:--:|:--:|
| JavaSecLab | 0.957 | 1.000 | 0.978 | 22 | 1 | 0 |
| SecExample | 0.889 | 1.000 | 0.941 | 8 | 1 | 0 |
| VulnerableApp | 0.900 | 0.900 | 0.900 | 9 | 1 | 1 |
| verademo | 0.929 | 1.000 | 0.963 | 13 | 1 | 0 |
| **Global** | **0.929** | **0.981** | **0.954** | **52** | **4** | **1** |

## Repository Structure

```text
eresus-appsec-skills/
├── README.md
├── LICENSE
├── assets/
│   ├── eresus-banner.svg
│   └── eresus-logo.svg
└── skills/
    ├── eresus-sast-scanner/
    │   ├── SKILL.md
    │   └── references/
    ├── eresus-remediator/
    │   └── SKILL.md
    ├── eresus-pr-security-review/
    │   └── SKILL.md
    ├── eresus-threat-modeler/
    │   └── SKILL.md
    └── eresus-serialization-review/
        └── SKILL.md
```

## Maintained By

Maintained under the **EresusSecurity** GitHub organization:

- [EresusSecurity GitHub Organization](https://github.com/organizations/EresusSecurity/)

## Contributing

Contributions that improve detection quality, reduce false positives, or strengthen language-specific coverage are welcome.

## License

Apache License 2.0
