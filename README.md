# AI/LLM Supply Chain Security Report

> ⚠️ **Security Alert** — LiteLLM TeamPCP Supply Chain Attack (2026-03-24)

This repository contains a multi-language security threat analysis report covering the LiteLLM PyPI supply chain attack and the broader implications for AI/LLM ecosystem security.

## 📄 Report Versions

| Language | File | Description |
|----------|------|-------------|
| 🇰🇷 한국어 | [security-report-ko.md](./security-report-ko.md) | 한국어 전문 리포트 |
| 🇺🇸 English | [security-report-en.md](./security-report-en.md) | Full English report |
| 🇨🇳 中文 | [security-report-zh.md]([./security-report-zh.md](https://github.com/gameworkerkim/AI-LLM-Supply-Chain-Security-Report/blob/main/Security%20report%20zh.MD)) | 完整中文报告 |

## 🚨 Quick Check

If you use `litellm`, run these commands **immediately**:

```bash
# Check version — remove if 1.82.7 or 1.82.8
pip show litellm

# Scan for malicious .pth file
find / -name "litellm_init.pth" 2>/dev/null

# Check for backdoor service
systemctl status sysmon.service 2>/dev/null
```

## 📋 Report Scope

- **Attack Summary**: TeamPCP group uploaded malicious `litellm v1.82.7` and `v1.82.8` to PyPI (~3 hours of exposure)
- **Historical Precedents**: event-stream (2018), ua-parser-js (2021), XZ Utils (2024), SolarWinds (2020)
- **Why AI/LLM attacks are more dangerous**: Excessive privilege, auto-trust culture, AI poisoning vectors
- **Nation-state dormant attack scenarios**: 3 realistic attack scenarios for state-sponsored APTs
- **Mitigation**: Immediate actions, short-term and long-term security strategies

## 🔗 References

- [BerriAI/litellm #24512](https://github.com/BerriAI/litellm/issues/24512)
- [BerriAI/litellm #24518](https://github.com/BerriAI/litellm/issues/24518)
- [CISA XZ Utils Advisory (CVE-2024-3094)](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-xz-utils-backdoor-cve-2024-3094)

---

*Published: 2026-03-25 | Classification: Security Sensitive — Internal Distribution Only*
