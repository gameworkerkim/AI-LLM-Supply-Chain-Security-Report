# Security Threat Analysis Report: AI/LLM Ecosystem Supply Chain Attack

> **The Rise of Dormant Cyber Threats and Defense Strategies**
>
> Analysis of the LiteLLM TeamPCP Supply Chain Attack (2026-03-24)  
> Claude Code Plugin · PyPI Ecosystem · Nation-State & Terrorist Group Threats
>
> Published: 2026-03-25 | Classification: Security Sensitive — Internal Distribution Only

---

> 🌐 **[한국어 버전](./security-report-ko.md)** | **[中文版本](./security-report-zh.md)**

---

## Table of Contents

1. [Overview & Executive Summary](#1-overview--executive-summary)
2. [LiteLLM TeamPCP Supply Chain Attack: Detailed Analysis](#2-litellm-teamcp-supply-chain-attack-detailed-analysis)
3. [Historical Precedents: npm/GitHub Ecosystem Supply Chain Attacks](#3-historical-precedents-npmgithub-ecosystem-supply-chain-attacks)
4. [Why AI/LLM Ecosystem Attacks Are More Lethal](#4-why-aillm-ecosystem-attacks-are-more-lethal)
5. [Dormant Attack Scenarios by Nation-States and Terrorist Groups](#5-dormant-attack-scenarios-by-nation-states-and-terrorist-groups)
6. [Current Environment Audit Results](#6-current-environment-audit-results-as-of-2026-03-25)
7. [Mitigation & Security Recommendations](#7-mitigation--security-recommendations)
8. [Conclusion](#8-conclusion)
9. [References](#references)

---

## 1. Overview & Executive Summary

This report provides a comprehensive analysis of the threat landscape following the **LiteLLM PyPI supply chain attack (TeamPCP)** on March 24, 2026 — examining the current state of supply chain attacks targeting the AI/LLM ecosystem, historical precedents, and future threat projections. The report specifically warns that as LLM-based development tools such as Claude Code Plugin and Obsidian AI plugins proliferate rapidly, **dormant attacks far more lethal and wide-reaching than traditional npm/GitHub ecosystem attacks** are increasingly likely.

| Field | Details |
|-------|---------|
| **Attack Name** | TeamPCP LiteLLM PyPI Supply Chain Attack |
| **Date** | 2026-03-24 (UTC) |
| **Affected Versions** | ⚠️ `litellm v1.82.7`, `v1.82.8` (malicious) |
| **Exposure Window** | ~3 hours (from PyPI upload to removal) |
| **Attack Vector** | Trivy CI/CD compromise → PyPI token theft → malicious package distribution |
| **Payload** | SSH key injection, API token & cloud credential theft, K8s lateral movement, systemd backdoor |
| **Affected Ecosystem** | Python/PyPI only (npm/JS unaffected) |
| **Threat Group** | TeamPCP (suspected nation-state affiliation) |

---

## 2. LiteLLM TeamPCP Supply Chain Attack: Detailed Analysis

### 2.1 Attack Timeline

On March 24, 2026, threat group TeamPCP uploaded a malicious litellm package to PyPI (Python Package Index). This was not a simple package tampering but a **sophisticated, multi-stage supply chain attack targeting trusted CI/CD infrastructure**.

| Stage | Description | Notes |
|-------|-------------|-------|
| Stage 1 | Compromise of Trivy security scanner CI/CD pipeline | Infrastructure trust collapsed |
| Stage 2 | Theft of PyPI publishing token from BerriAI/litellm repository | Credential exfiltration |
| Stage 3 | Malicious `litellm v1.82.7` / `v1.82.8` uploaded to PyPI | Disguised as legitimate release |
| Stage 4 | Propagation via automated dependency update tools (Dependabot, etc.) | ~3 hours of exposure |
| Stage 5 | PyPI team notified → packages removed | Downloads occurred before removal |

### 2.2 Malicious Payload Analysis

The injected malicious code was far beyond simple data collection — it was an **APT (Advanced Persistent Threat)-grade payload** designed for long-term persistence and lateral movement.

- **SSH public key injection**: Attacker's SSH key registered in `~/.ssh/authorized_keys` for persistent remote access
- **API token & cloud credential theft**: Collection of AWS, GCP, Azure environment variables and `~/.aws/credentials`, `~/.config/gcloud`
- **Kubernetes lateral movement**: Lateral movement via service account tokens within the cluster
- **systemd backdoor service registration**: Persistent backdoor disguised as `sysmon.service`, surviving system reboots
- **C2 (Command & Control) beacon**: Periodic check-ins to attacker server and command reception

> ⚠️ **Critical Risk Factors**
> - API keys stolen from developer environments connect directly to production systems
> - LLM API keys (OpenAI, Anthropic, Google) theft enables unauthorized AI service use and prompt eavesdropping
> - Lateral movement capability allows expansion to full cluster compromise in K8s environments
> - systemd service registration maintains the backdoor through system restarts

---

## 3. Historical Precedents: npm/GitHub Ecosystem Supply Chain Attacks

To understand the LiteLLM attack, we must first understand the supply chain attack patterns seen in prior ecosystems.

### 3.1 event-stream Incident (2018, npm)

In November 2018, malicious code was inserted into the npm package `event-stream`, which recorded approximately 2 million weekly downloads. The attacker received ownership transfer from the package maintainer and concealed malicious code through a dependency called `flatmap-stream`.

- **Target**: Copay Bitcoin wallet app users
- **Payload**: Private wallet key and balance theft
- **Exposure**: ~2 months (until discovery)
- **Lesson**: Trust transfer (maintainer ownership handover) weaponized as an attack vector

### 3.2 ua-parser-js Hijacking (2021, npm)

The `ua-parser-js` package — recording tens of millions of weekly downloads — was replaced with 3 malicious versions (`0.7.29`, `0.8.0`, `1.0.0`) via npm account takeover.

- **Payload**: Cryptominer + password/token theft
- **Impact**: Direct impact on CI/CD pipelines at Fortune 500 companies including Facebook, Microsoft
- **Exposure**: ~4 hours
- **Lesson**: Popularity amplifies damage exponentially due to automatic trust

### 3.3 colors.js / faker.js Sabotage (2022, npm)

Package author Marak Squires intentionally inserted an infinite loop into his own packages, paralyzing thousands of services.

- **Impact**: AWS CDK and thousands of open-source projects immediately disrupted
- **Lesson**: Insider Threat — even original authors can no longer be unconditionally trusted

### 3.4 XZ Utils Backdoor (2024, Linux)

Attacker 'Jia Tan' contributed as an open-source contributor for **~2 years**, building trust before inserting an SSH authentication bypass backdoor into the `liblzma` library.

- **Dormancy**: ~2 years (2022–2024)
- **Impact**: Direct compromise of SSH servers on major Linux distributions including Debian, Fedora, Arch
- **Nation-state suspected**: Sophistication and patience suggest a state-sponsored APT group
- **Lesson**: Long-term dormant attacks (slow-burn APT) have become a reality in the open-source ecosystem

### 3.5 SolarWinds Orion Supply Chain Attack (2020)

APT29 (Cozy Bear), affiliated with Russia's SVR, infiltrated SolarWinds' build system and distributed malicious software to over 18,000 organizations — one of the most serious supply chain attacks in history.

- **Dormancy**: ~14 months (October 2019 to discovery in December 2020)
- **Damage**: US government agencies (DoD, Treasury, DHS, etc.) and Fortune 500 companies
- **Method**: SUNBURST backdoor inserted into legitimate software updates
- **Lesson**: Trusted software distribution channels are the ultimate attack vector

### Supply Chain Attack Comparison

| Incident | Year | Ecosystem | Dormancy | Severity |
|----------|------|-----------|---------|---------|
| event-stream | 2018 | npm | ~2 months | Medium |
| ua-parser-js | 2021 | npm | ~4 hours | High |
| XZ Utils | 2024 | Linux | **~2 years** | **Critical** |
| SolarWinds | 2020 | Enterprise | **~14 months** | **Critical** |
| **LiteLLM (TeamPCP)** | **2026** | **PyPI/AI** | **~3 hours** | **Under Investigation** |

---

## 4. Why AI/LLM Ecosystem Attacks Are More Lethal

While traditional npm/PyPI supply chain attacks were already dangerous, attacks targeting the LLM ecosystem carry a far greater **blast radius** due to structural and functional characteristics.

### 4.1 LLM Tools Run with Excessive Privilege

AI coding assistants such as Claude Code, Cursor, and Copilot require broad permissions by design — file system read/write, terminal execution, environment variable access, and network requests.

- **Standard npm library**: Limited permissions for specific functionality
- **LLM plugin/MCP server**: Access to the entire developer local environment
- An attacker can exfiltrate codebases, SSH keys, API tokens, and cloud credentials **all at once** through a compromised LLM tool

> **→ A single backdoor in an LLM tool can steal 10x more information than a traditional attack in one shot.**

### 4.2 AI Tools Have Cultivated a Culture of "Automatic Trust"

Developers' reliance on AI tool convenience leads to skipping security reviews during plugin installation.

- Claude Code Extension, MCP servers, etc. run with high privileges immediately upon installation
- Psychological trust in "AI-recommended packages" dulls security instincts
- Pursuit of rapid productivity leads to frequent omission of basic security practices like lock file pinning and version verification

### 4.3 "AI Poisoning" Attacks Through the LLM Itself

When malicious plugins directly access or modify an LLM's context:

- **Prompt Injection**: Malicious code injects adversarial instructions into the LLM
- **Training Data Poisoning**: Backdoors inserted into LLM fine-tuning data
- **Model Exfiltration**: Theft of proprietary fine-tuned model weights
- **Context Window Eavesdropping**: Interception of sensitive code, data, and secrets passed to the LLM

> **→ This is not a code-level attack but an intelligence-level attack, making defensive detection extremely difficult.**

### 4.4 Deep CI/CD Integration Maximizes Lateral Movement Scope

LLM frameworks like LiteLLM, LangChain, and AutoGPT are deeply integrated into modern CI/CD pipelines.

- Growing use of LLM-based code review and test automation in GitHub Actions, Jenkins, GitLab CI
- Compromised LLM tools connect directly to production environments through CI/CD pipelines
- Compromise of LLM workloads within K8s clusters exposes the entire microservices environment

### 4.5 Explosive Growth of the LLM Ecosystem = Rapidly Expanding Attack Surface

| Metric | 2023 | 2026 (Projected) |
|--------|------|-----------------|
| Monthly litellm PyPI downloads | ~500K | ~20M+ |
| Claude Code daily active users | Small early adopter base | Millions |
| MCP servers/plugins | Dozens | Thousands |
| LLM-integrated CI/CD pipelines | Experimental | Industry standardization underway |

---

## 5. Dormant Attack Scenarios by Nation-States and Terrorist Groups

As confirmed by the XZ Utils incident, nation-state-sponsored APT groups already possess the capability to conduct multi-year dormant attacks within the open-source ecosystem. The AI/LLM ecosystem is a far more attractive target for them.

### 5.1 Slow-Burn Attack Scenarios

#### 🔴 Scenario A: Open-Source Contributor Impersonation (XZ Utils Method)

1. Attacker makes legitimate contributions to a prominent MCP server repository (e.g., `claude-mcp-filesystem`) for several months
2. Builds trust and gains maintainer privileges
3. Inserts a detection-resistant backdoor in a minor release (obfuscation, conditional execution)
4. Automatically distributed to all Claude Code users; enters long-term dormancy
5. **Payload activates only on designated targets (government contractors, defense firms, etc.)**

#### 🟠 Scenario B: PyPI/npm Package Hijacking (Advanced LiteLLM Method)

1. Theft of CI/CD tokens from popular LLM frameworks
2. Malicious version uploaded during vulnerable time windows (weekends, holidays)
3. Propagated to thousands of projects via automated tools like Dependabot
4. Stolen cloud credentials used to compromise production infrastructure

#### 🟡 Scenario C: AI Model Supply Chain Attack (Next-Generation Threat)

1. Upload of backdoored fine-tuned model to model hubs like HuggingFace
2. Disguised as a legitimate model; integrated into enterprise RAG/fine-tuning pipelines
3. Sensitive data exfiltration or incorrect responses triggered upon detecting specific prompt patterns
4. **Manipulation of LLM-based decision-making systems in finance, healthcare, and defense sectors**

### 5.2 Why the AI Ecosystem Is Attractive to Nation-State Actors

> ℹ️ **Strategic Value Analysis**
> - Developer environment compromise → source code theft: access to confidential corporate/government codebases
> - API key theft → AI service abuse: large-scale disinformation generation, cyberattack automation
> - LLM context eavesdropping → intelligence collection: real-time interception of corporate strategy, technical designs, and personal data
> - Large-scale propagation through supply chain: simultaneous infection of millions of developers from a single attack
> - Detection evasion: complex dependency graphs of AI tools facilitate concealment of malicious code

### 5.3 Threat Actor Typology and Motivations

| Threat Actor | Primary Targets | Expected Attack Method | Possible Dormancy |
|-------------|----------------|----------------------|------------------|
| **Nation-State APT** (Russia, China, North Korea, etc.) | Government, defense, finance, AI research institutions | XZ Utils-style long-term open-source infiltration | **1–3 years** |
| Cyber Terrorist Groups | Critical infrastructure, financial systems | PyPI/npm hijacking | Days–weeks |
| Cybercriminal Organizations | Cryptocurrency, personal credentials | Package typosquatting | Hours–days |
| Hacktivists | Specific corporations/organizations | Software sabotage | Immediate–weeks |

---

## 6. Current Environment Audit Results (As of 2026-03-25)

The audit covers 6 Claude Code-integrated plugins and 10 Obsidian AI plugins, totaling 16 plugins.

### 6.1 Claude Code Plugin Audit

| Plugin | litellm Dependency | Version Status | Verdict |
|--------|-------------------|----------------|---------|
| Ouroboros v0.25.0 | ⚠️ Yes (>=1.80.0) | lock: pinned to 1.82.1 | ✅ Safe |
| superpowers | None | N/A | ✅ Not Affected |
| ralph | None | N/A | ✅ Not Affected |
| claude-mem | None | N/A | ✅ Not Affected |
| claude-hud | None | N/A | ✅ Not Affected |
| obsidian-skills | None | N/A | ✅ Not Affected |

### 6.2 Obsidian Plugin Audit

All 10 Obsidian plugins audited (calendar, claudian, dataview, templater, etc.) are **JavaScript-based** and have no dependency on the Python/PyPI ecosystem. They are unaffected by this LiteLLM attack.

### 6.3 System-Level Audit Results

> ✅ **Current Environment: No Compromise Confirmed**
> - litellm not installed in system Python (`pip show litellm` → not found)
> - Malicious `.pth` file (`litellm_init.pth`) not detected
> - Backdoor service (`sysmon.service`) not registered
> - Ouroboros MCP process not currently running

### 6.4 Self-Audit Commands

Run the following commands immediately to check your own environment:

```bash
# 1. Check litellm version (remove immediately if 1.82.7 or 1.82.8)
pip show litellm

# 2. Search for malicious .pth file
find / -name "litellm_init.pth" 2>/dev/null

# 3. Check for backdoor service
systemctl status sysmon.service 2>/dev/null

# 4. Check authorized_keys integrity
cat ~/.ssh/authorized_keys | wc -l  # verify no unexpected entries
```

---

## 7. Mitigation & Security Recommendations

### 7.1 Immediate Actions

> ⚠️ **Emergency Checklist — Act Now**
> - `pip show litellm` → if 1.82.7/1.82.8, run `pip install litellm==1.82.6` or `pip install litellm --upgrade` immediately
> - `pip install pip-audit && pip-audit` to scan entire Python environment for vulnerabilities
> - Review `authorized_keys` and immediately remove any unrecognized public keys
> - Rotate AWS/GCP/Azure API keys (invalidate immediately if exposure is suspected)
> - Audit LLM API credentials including Anthropic API keys, OpenAI API keys

### 7.2 Short-Term Response (1–4 Weeks)

1. **Dependency Pinning**: Pin exact versions in `requirements.txt` or `pyproject.toml` (e.g., `litellm==X.X.X`)
2. **Enforce Lock Files**: Mandate hash-based lock files (`pip-compile`, `poetry.lock`, `pdm.lock`) and validate in CI/CD
3. **Generate SBOM (Software Bill of Materials)**: Regularly generate full dependency lists and monitor for vulnerabilities
4. **PyPI Package Signature Verification**: Verify package integrity via PEP 740 attestations or Sigstore
5. **Minimize MCP Server Permissions**: Explicitly restrict the filesystem access scope of MCP servers used by Claude Code

### 7.3 Medium-to-Long-Term Strategy (1–6 Months)

- **Zero Trust for AI Tools**: Apply the same security review standards to LLM plugins and tools as to regular code
- **AI Tool Sandboxing**: Run Claude Code and other AI assistants in Docker/container-based isolated environments
- **Supply Chain Threat Intelligence Subscription**: Adopt supply chain security services like Wiz, Snyk, and Socket.dev
- **Strengthen Open-Source Contributor Identity Verification**: Implement Contributor Verification policies in core LLM tool repositories
- **AI Tool Usage Audit Logs**: Record network requests and file access by LLM plugins; implement anomaly detection

### 7.4 Organizational Governance

| Domain | Recommendation |
|--------|---------------|
| **Policy** | Mandatory security review before adopting any AI tool (Security Review Gate) |
| **Training** | Regular supply chain attack awareness training for developers (at least twice per year) |
| **Infrastructure** | Operate internal PyPI/npm mirrors and enforce approved-package-only policies |
| **Monitoring** | Build real-time SBOM-based CVE vulnerability alerting systems |
| **Response** | Establish supply chain compromise response runbooks and conduct regular drills |

---

## 8. Conclusion

The LiteLLM TeamPCP attack is a harbinger of sophisticated supply chain attacks targeting the AI/LLM ecosystem. Key reasons for concern:

- **Targets environments with far greater privilege than traditional npm/PyPI attacks**
- **Developers' psychological trust in AI tools dulls their security instincts**
- **Intelligence collection through LLM context access is extremely difficult to detect**
- **Nation-state actors are already conducting dormant attacks in the open-source ecosystem**
- **The explosive growth of the AI ecosystem is exponentially expanding the attack surface**

As the XZ Utils incident proved, nation-state-sponsored APT groups are capable of compromising core open-source tools while accepting **over 2 years of dormancy**. Claude Code Plugins, MCP servers, and LLM frameworks are dozens of times more attractive targets than previous generations of attack vectors — because a single compromise can grant access to the environments of millions of developers.

We must immediately cultivate a security culture that treats AI tools not as "trusted colleagues" but as **"external code."** Convenience matters, but **unverified trust is the most dangerous vulnerability.**

> ⚠️ **Key Takeaways**
> 1. Check your litellm version right now (`1.82.7`/`1.82.8` → remove immediately)
> 2. All AI tools must undergo security review before installation
> 3. Dependency pinning and lock file validation are mandatory, not optional
> 4. Supply chain attacks have already begun — the next attack will be even more sophisticated

---

## References

- [BerriAI/litellm GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512) — Official LiteLLM supply chain attack timeline
- [BerriAI/litellm GitHub Issue #24518](https://github.com/BerriAI/litellm/issues/24518) — Incident response details
- Wiz Blog: TeamPCP LiteLLM Supply Chain Attack Analysis
- The Hacker News: TeamPCP Backdoors LiteLLM Versions 1.82.7–1.82.8
- [CISA Advisory: XZ Utils Backdoor (CVE-2024-3094)](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-xz-utils-backdoor-cve-2024-3094)
- [OpenSSF: Secure Supply Chain Consumption Framework (S2C2F)](https://github.com/ossf/s2c2f)
- [SLSA (Supply chain Levels for Software Artifacts) Framework](https://slsa.dev/)
- [PEP 740 – Index support for digital attestations](https://peps.python.org/pep-0740/)
- [Socket.dev: Real-time supply chain attack detection](https://socket.dev/)

---

*This report was prepared for security awareness and internal training purposes.*
