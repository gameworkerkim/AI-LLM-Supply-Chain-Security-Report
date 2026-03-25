# 安全威胁分析报告：AI/LLM 生态系统供应链攻击

> **潜伏型网络威胁的崛起与防御策略**
>
> LiteLLM TeamPCP 供应链攻击事件分析（2026-03-24）  
> Claude Code Plugin · PyPI 生态系统 · 国家及恐怖组织威胁
>
> 发布日期：2026-03-25 | 分类：安全敏感 — 仅限内部发布

---

> 🌐 **[한국어 버전](./security-report-ko.md)** | **[English Version](./security-report-en.md)**

---

## 目录

1. [概述与执行摘要](#1-概述与执行摘要)
2. [LiteLLM TeamPCP 供应链攻击详细分析](#2-litellm-teamcp-供应链攻击详细分析)
3. [历史先例：npm/GitHub 生态系统供应链攻击](#3-历史先例npmgithub-生态系统供应链攻击)
4. [AI/LLM 生态系统攻击为何更具致命性](#4-aillm-生态系统攻击为何更具致命性)
5. [国家及恐怖组织的潜伏型攻击场景](#5-国家及恐怖组织的潜伏型攻击场景)
6. [当前环境检查结果](#6-当前环境检查结果2026-03-25-基准)
7. [应对措施与安全建议](#7-应对措施与安全建议)
8. [结论](#8-结论)
9. [参考资料](#参考资料)

---

## 1. 概述与执行摘要

本报告以 2026 年 3 月 24 日发生的 **LiteLLM PyPI 供应链攻击（TeamPCP）** 为起点，综合分析了针对 AI/LLM 生态系统的供应链攻击现状、历史先例及未来威胁展望。本报告特别警告：随着 Claude Code Plugin、Obsidian AI 插件等基于 LLM 的开发工具迅速普及，**比传统 npm/GitHub 生态系统攻击更具致命性且波及范围更广的潜伏型（dormant）攻击**发生的可能性正在急剧上升。

| 字段 | 内容 |
|------|------|
| **攻击名称** | TeamPCP LiteLLM PyPI 供应链攻击 |
| **发生时间** | 2026-03-24（UTC） |
| **受影响版本** | ⚠️ `litellm v1.82.7`、`v1.82.8`（恶意版本） |
| **暴露时长** | 约 3 小时（从上传至 PyPI 到被删除） |
| **攻击向量** | Trivy CI/CD 入侵 → PyPI 令牌盗取 → 恶意包发布 |
| **有效载荷** | SSH 密钥注入、API 令牌及云凭据窃取、K8s 横向移动、systemd 后门 |
| **受影响生态** | 仅 Python/PyPI（npm/JS 不受影响） |
| **威胁组织** | TeamPCP（疑似国家关联） |

---

## 2. LiteLLM TeamPCP 供应链攻击详细分析

### 2.1 攻击时间线

2026 年 3 月 24 日，威胁组织 TeamPCP 向 PyPI（Python Package Index）上传了恶意 litellm 包。此次攻击绝非简单的包篡改，而是一次**针对可信 CI/CD 基础设施的精密多阶段供应链攻击**。

| 阶段 | 内容 | 备注 |
|------|------|------|
| 第 1 阶段 | 入侵 Trivy 安全扫描器 CI/CD 流水线 | 基础设施信任体系崩溃 |
| 第 2 阶段 | 盗取 BerriAI/litellm 仓库的 PyPI 发布令牌 | 凭据窃取 |
| 第 3 阶段 | 将恶意 `litellm v1.82.7` / `v1.82.8` 上传至 PyPI | 伪装成正常发布版本 |
| 第 4 阶段 | 通过自动化依赖更新工具（Dependabot 等）传播 | 约 3 小时暴露期 |
| 第 5 阶段 | PyPI 团队收到举报 → 删除包 | 删除前已产生下载 |

### 2.2 恶意有效载荷分析

植入的恶意代码远不止简单的信息收集，而是专为长期潜伏和横向移动设计的 **APT（高级持续性威胁）级别有效载荷**。

- **SSH 公钥注入**：将攻击者 SSH 密钥写入 `~/.ssh/authorized_keys`，建立永久远程访问
- **API 令牌及云凭据窃取**：收集 AWS、GCP、Azure 环境变量及 `~/.aws/credentials`、`~/.config/gcloud`
- **Kubernetes 横向移动**：利用集群内服务账户令牌进行 lateral movement
- **systemd 后门服务注册**：伪装为 `sysmon.service` 的持久化后门，系统重启后依然存活
- **C2（指挥控制）信标**：定期向攻击者服务器发送心跳包并接收指令

> ⚠️ **致命风险因素**
> - 从开发环境盗取的 API 密钥直接连接到生产系统
> - LLM API 密钥（OpenAI、Anthropic、Google）被盗后可被用于未授权的 AI 服务访问及提示词监听
> - 在 K8s 环境中，横向移动能力可扩展至整个集群的全面入侵
> - systemd 服务注册使后门在系统重启后依然存在

---

## 3. 历史先例：npm/GitHub 生态系统供应链攻击

要理解 LiteLLM 攻击，必须先了解此前生态系统中发生的供应链攻击模式。

### 3.1 event-stream 事件（2018，npm）

2018 年 11 月，每周下载量约 200 万次的 npm 包 `event-stream` 被植入恶意代码。攻击者从软件包维护者处获得所有权转让后，通过名为 `flatmap-stream` 的依赖项隐藏了恶意代码。

- **目标**：Copay 比特币钱包应用用户
- **有效载荷**：私人钱包密钥及余额窃取
- **暴露期**：约 2 个月（发现前）
- **教训**：维护者信任转移（Trust Transfer）被武器化为攻击向量

### 3.2 ua-parser-js 劫持（2021，npm）

每周下载量数千万的 `ua-parser-js` 包通过 npm 账户劫持被替换为 3 个恶意版本（`0.7.29`、`0.8.0`、`1.0.0`）。

- **有效载荷**：加密货币挖矿程序 + 密码/令牌窃取
- **影响**：直接波及 Facebook、Microsoft 等财富 500 强企业的 CI/CD 流水线
- **暴露时长**：约 4 小时
- **教训**：包越流行，由于自动信任机制，受损规模呈指数级增长

### 3.3 colors.js / faker.js 破坏（2022，npm）

包原作者 Marak Squires 故意在自己的包中插入无限循环代码，导致数千个服务瘫痪。

- **影响**：AWS CDK 及数千个开源项目立即中断
- **教训**：内部威胁（Insider Threat）——连原作者也无法无条件信任的时代已经到来

### 3.4 XZ Utils 后门（2024，Linux）

攻击者"Jia Tan"以开源贡献者身份活动约 **2 年**，建立信任后，在 `liblzma` 库中植入了可绕过 SSH 认证的后门。

- **潜伏期**：约 2 年（2022~2024 年）
- **影响**：直接入侵 Debian、Fedora、Arch 等主流 Linux 发行版的 SSH 服务器
- **疑似国家行为者**：其精密程度与耐心推测为国家支持的 APT 组织
- **教训**：长期潜伏型攻击（慢燃 APT）已在开源生态系统中成为现实

### 3.5 SolarWinds Orion 供应链攻击（2020）

隶属俄罗斯 SVR 的 APT29（Cozy Bear）渗透了 SolarWinds 的构建系统，向超过 18,000 个组织分发恶意软件，是历史上最严重的供应链攻击之一。

- **潜伏期**：约 14 个月（2019 年 10 月至 2020 年 12 月发现）
- **受损方**：美国政府机构（国防部、财政部、DHS 等）及财富 500 强企业
- **攻击方式**：在正常软件更新中植入 SUNBURST 后门
- **教训**：受信任的软件分发渠道是最高效的攻击向量

### 供应链攻击对比

| 事件名称 | 年份 | 生态系统 | 潜伏期 | 损害程度 |
|---------|------|---------|-------|---------|
| event-stream | 2018 | npm | ~2 个月 | 中等 |
| ua-parser-js | 2021 | npm | ~4 小时 | 高 |
| XZ Utils | 2024 | Linux | **~2 年** | **致命** |
| SolarWinds | 2020 | 企业级 | **~14 个月** | **致命** |
| **LiteLLM（TeamPCP）** | **2026** | **PyPI/AI** | **~3 小时** | **调查中** |

---

## 4. AI/LLM 生态系统攻击为何更具致命性

传统 npm/PyPI 供应链攻击已足够危险，但针对 LLM 生态系统的攻击因其结构性和功能性特点，具有远更高的**爆炸半径（Blast Radius）**。

### 4.1 LLM 工具以过度权限运行

Claude Code、Cursor、Copilot 等 AI 编程助手在设计上需要文件系统读写、终端执行、环境变量访问、网络请求等极为广泛的权限。

- **普通 npm 库**：仅限特定功能的受限权限
- **LLM 插件/MCP 服务器**：对开发者本地整个环境的访问权限
- 攻击者可通过受损的 LLM 工具**一次性**窃取代码库、SSH 密钥、API 令牌和云凭据

> **→ LLM 工具中植入的单个后门，可一次窃取传统攻击 10 倍以上的信息。**

### 4.2 AI 工具已形成"自动信任"文化

开发者依赖 AI 工具的便利性，在安装插件时倾向于跳过安全审查。

- Claude Code Extension、MCP 服务器等安装后即以高权限运行
- 对"AI 推荐的包"的心理信任使安全意识变得迟钝
- 追求快速生产力导致频繁省略 lock 文件固定、版本验证等基本安全流程

### 4.3 通过 LLM 本身进行"AI 投毒（AI Poisoning）"攻击

当恶意插件直接访问或修改 LLM 的上下文时：

- **提示词注入（Prompt Injection）**：恶意代码向 LLM 注入恶意指令
- **训练数据投毒（Training Data Poisoning）**：向 LLM 微调数据中植入后门
- **模型泄露（Model Exfiltration）**：窃取专有微调模型权重
- **上下文窗口监听（Context Window Eavesdropping）**：拦截传递给 LLM 的敏感代码、数据和密钥

> **→ 这不是代码级攻击，而是情报级攻击，防御检测极为困难。**

### 4.4 与 CI/CD 深度集成极大化横向移动范围

LiteLLM、LangChain、AutoGPT 等 LLM 框架已深度集成到现代 CI/CD 流水线中。

- GitHub Actions、Jenkins、GitLab CI 中基于 LLM 的代码审查和测试自动化使用日益增加
- 受损的 LLM 工具通过 CI/CD 流水线直接连接到生产环境
- K8s 集群内 LLM 工作负载被入侵时，整个微服务环境面临暴露

### 4.5 LLM 生态系统的爆炸性增长 = 急剧扩张的攻击面

| 指标 | 2023 | 2026（预测） |
|------|------|------------|
| litellm PyPI 月度下载量 | ~50 万 | ~2000 万以上 |
| Claude Code 日活跃用户 | 少数早期采用者 | 数百万 |
| MCP 服务器/插件数量 | 数十个 | 数千个 |
| LLM 集成 CI/CD 流水线 | 实验性 | 行业标准化推进中 |

---

## 5. 国家及恐怖组织的潜伏型攻击场景

XZ Utils 事件证明，国家支持的 APT 组织已具备在开源生态系统中实施多年潜伏型攻击的能力。AI/LLM 生态系统对他们来说是更具吸引力的目标。

### 5.1 慢燃型（Slow-burn）攻击场景

#### 🔴 场景 A：伪装成开源贡献者（XZ Utils 方式）

1. 攻击者在知名 MCP 服务器（如 `claude-mcp-filesystem`）仓库中进行数月的正常贡献
2. 建立信任关系后获取 maintainer 权限
3. 在次要版本中植入难以检测的后门（混淆、条件执行）
4. 自动分发至所有 Claude Code 用户后进入长期潜伏
5. **仅在指定目标（政府承包商、国防企业等）处激活有效载荷**

#### 🟠 场景 B：PyPI/npm 包劫持（LiteLLM 方式升级版）

1. 盗取流行 LLM 框架的 CI/CD 令牌
2. 在脆弱时间段（周末、节假日）上传恶意版本
3. 通过 Dependabot 等自动化工具传播至数千个项目
4. 利用窃取的云凭据入侵生产基础设施

#### 🟡 场景 C：AI 模型供应链攻击（下一代威胁）

1. 向 HuggingFace 等模型中心上传植入后门的微调模型
2. 伪装成正常模型，被集成到企业的 RAG/微调流水线中
3. 检测到特定提示词模式时触发敏感数据泄露或错误响应生成
4. **操控金融、医疗、国防领域基于 LLM 的决策系统**

### 5.2 AI 生态系统对国家行为者具有吸引力的原因

> ℹ️ **战略价值分析**
> - 开发者环境入侵 → 源代码窃取：访问企业/政府机密代码库
> - API 密钥盗取 → AI 服务滥用：大规模虚假信息生成、网络攻击自动化
> - LLM 上下文监听 → 情报收集：实时拦截企业战略、技术设计和个人信息
> - 通过供应链大规模传播：单次攻击可同时感染数百万开发者
> - 规避检测：AI 工具复杂的依赖关系图使恶意代码易于隐藏

### 5.3 威胁行为者类型及动机

| 威胁行为者 | 主要目标 | 预期攻击方式 | 可能潜伏期 |
|-----------|---------|-----------|---------|
| **国家支持 APT**（俄罗斯、中国、朝鲜等） | 政府、国防、金融、AI 研究机构 | XZ Utils 型长期开源渗透 | **1~3 年** |
| 网络恐怖组织 | 关键基础设施、金融系统 | PyPI/npm 劫持 | 数日~数周 |
| 网络犯罪组织 | 加密货币、个人凭据 | 包名抢注（Typosquatting） | 数小时~数日 |
| 黑客行动主义者 | 特定企业/组织 | 软件破坏 | 即时~数周 |

---

## 6. 当前环境检查结果（2026-03-25 基准）

检查对象为 6 个 Claude Code 集成插件和 10 个 Obsidian AI 插件，共 16 个插件。

### 6.1 Claude Code 相关插件检查

| 插件 | litellm 依赖 | 版本状态 | 判定 |
|------|------------|---------|------|
| Ouroboros v0.25.0 | ⚠️ 有（>=1.80.0） | lock：固定为 1.82.1 | ✅ 安全 |
| superpowers | 无 | 不适用 | ✅ 不受影响 |
| ralph | 无 | 不适用 | ✅ 不受影响 |
| claude-mem | 无 | 不适用 | ✅ 不受影响 |
| claude-hud | 无 | 不适用 | ✅ 不受影响 |
| obsidian-skills | 无 | 不适用 | ✅ 不受影响 |

### 6.2 Obsidian 插件检查

检查对象的 10 个 Obsidian 插件（calendar、claudian、dataview、templater 等）全部基于 **JavaScript** 实现，与 Python/PyPI 生态系统无关。不受本次 LiteLLM 攻击影响。

### 6.3 系统级检查结果

> ✅ **当前环境：确认未被入侵**
> - 确认系统 Python 中未安装 litellm（`pip show litellm` → not found）
> - 未检测到恶意 `.pth` 文件（`litellm_init.pth`）
> - 未注册后门服务（`sysmon.service`）
> - Ouroboros MCP 进程当前未运行

### 6.4 自检命令

可立即通过以下命令检查自己的环境：

```bash
# 1. 检查 litellm 版本（如为 1.82.7 或 1.82.8 立即处理）
pip show litellm

# 2. 搜索恶意 .pth 文件
find / -name "litellm_init.pth" 2>/dev/null

# 3. 检查后门服务
systemctl status sysmon.service 2>/dev/null

# 4. 检查 authorized_keys 完整性
cat ~/.ssh/authorized_keys | wc -l  # 确认无意外条目
```

---

## 7. 应对措施与安全建议

### 7.1 立即行动（Immediate Actions）

> ⚠️ **紧急检查项目 — 立即执行**
> - `pip show litellm` → 如为 1.82.7/1.82.8，立即执行 `pip install litellm==1.82.6` 或 `pip install litellm --upgrade`
> - `pip install pip-audit && pip-audit` 对整个 Python 环境进行漏洞扫描
> - 审查 `authorized_keys`，立即删除不明公钥
> - 轮换 AWS/GCP/Azure API 密钥（疑似泄露时立即失效）
> - 检查 Anthropic API 密钥、OpenAI API 密钥等 LLM API 凭据

### 7.2 短期应对（1~4 周）

1. **依赖固定（Dependency Pinning）**：在 `requirements.txt` 或 `pyproject.toml` 中以 `litellm==X.X.X` 格式固定精确版本
2. **强制使用 lock 文件**：在 CI/CD 中强制验证基于哈希的 lock 文件（`pip-compile`、`poetry.lock`、`pdm.lock` 等）
3. **生成 SBOM（软件物料清单）**：定期生成项目完整依赖列表并监控漏洞
4. **PyPI 包签名验证**：通过 PEP 740 attestation 或 Sigstore 验证包完整性
5. **最小化 MCP 服务器权限**：明确限制 Claude Code 使用的 MCP 服务器的文件系统访问范围

### 7.3 中长期策略（1~6 个月）

- **AI 工具零信任（Zero Trust for AI Tools）**：对 LLM 插件和工具采用与普通代码相同的安全审查标准
- **AI 工具沙箱化**：在基于 Docker/容器的隔离环境中运行 Claude Code 等 AI 助手
- **订阅供应链威胁情报**：引入 Wiz、Snyk、Socket.dev 等专注于供应链安全的服务
- **加强开源贡献者身份验证**：在核心 LLM 工具仓库中实施贡献者验证（Contributor Verification）政策
- **AI 工具使用审计日志**：记录 LLM 插件的网络请求和文件访问日志，实施异常检测

### 7.4 组织层面治理

| 领域 | 建议事项 |
|------|---------|
| **政策** | 引入 AI 工具前强制安全审查（Security Review Gate） |
| **培训** | 定期对开发者开展供应链攻击意识培训（每年至少 2 次） |
| **基础设施** | 运营内部 PyPI/npm 镜像，实施仅允许使用已批准包的政策 |
| **监控** | 构建基于 SBOM 的 CVE 漏洞实时预警体系 |
| **响应** | 制定供应链入侵响应手册（Runbook）并定期演练 |

---

## 8. 结论

LiteLLM TeamPCP 攻击是针对 AI/LLM 生态系统的精密供应链攻击拉开帷幕的信号弹。该攻击令人特别忧虑的原因：

- **针对的环境权限远高于传统 npm/PyPI 攻击**
- **开发者对 AI 工具的心理信任使安全意识变得迟钝**
- **通过 LLM 上下文访问进行的信息收集极难被检测**
- **国家行为者已在开源生态系统中实施潜伏型攻击**
- **AI 生态系统的爆炸性增长正在以指数级速度扩大攻击面**

正如 XZ Utils 事件所证明的，国家支持的 APT 组织具备在承受**超过 2 年潜伏期**的同时入侵核心开源工具的能力。Claude Code Plugin、MCP 服务器、LLM 框架对他们来说，比上一代攻击目标具有数十倍的吸引力——因为单次入侵即可获得对数百万开发者整个环境的访问权限。

我们必须立即建立将 AI 工具视为**"外部代码"而非"可信伙伴"**的安全文化。便利性固然重要，但**未经验证的信任是最危险的漏洞**。

> ⚠️ **核心信息**
> 1. 立即检查 litellm 版本（`1.82.7`/`1.82.8` → 立即删除）
> 2. 所有 AI 工具在安装前必须经过安全审查
> 3. 依赖固定和 lock 文件验证是必须项，而非可选项
> 4. 供应链攻击已经开始，下一次攻击将更加精密

---

## 参考资料

- [BerriAI/litellm GitHub Issue #24512](https://github.com/BerriAI/litellm/issues/24512) — LiteLLM 供应链攻击官方时间线
- [BerriAI/litellm GitHub Issue #24518](https://github.com/BerriAI/litellm/issues/24518) — 事件响应详情
- Wiz Blog：TeamPCP LiteLLM 供应链攻击分析
- The Hacker News：TeamPCP Backdoors LiteLLM Versions 1.82.7–1.82.8
- [CISA Advisory：XZ Utils Backdoor（CVE-2024-3094）](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-xz-utils-backdoor-cve-2024-3094)
- [OpenSSF：安全供应链消费框架（S2C2F）](https://github.com/ossf/s2c2f)
- [SLSA（软件制品供应链级别）框架](https://slsa.dev/)
- [PEP 740 – 数字认证的索引支持](https://peps.python.org/pep-0740/)
- [Socket.dev：实时供应链攻击检测](https://socket.dev/)

---

*本报告仅用于安全意识提升及内部培训目的。*
