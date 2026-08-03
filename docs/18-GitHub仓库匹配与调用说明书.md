# 报告一：GitHub 仓库匹配与分析调用说明书

> 目标场景：让 Hermes 从「固定 localhost 教学流水线」走向「在 Bugcrowd 授权 program 上做真实漏洞分析并产出可提交报告」。
> 本说明书筛选可**直接调用 / 二次开发 / 参考借鉴**的开源仓库，并映射到 Hermes 现有架构节点。
> 研究快照时间：2026-08。**Star/许可/活跃度会变，采用前须复核仓库当前 LICENSE 与 program 的自动化政策。**
> 定位：防御性/授权测试用途。所有「攻击性」能力仅在**有明确 RoE 的授权 program**内、并遵守其自动化政策时使用。

---

## 0. 筛选标准与「复用方式」定义

| 复用方式 | 含义 | 对 Hermes 的影响 |
|---|---|---|
| **直接调用** | 作为外部工具/服务被 Hermes Gateway 调度（CLI 或 MCP），不改其代码 | 最小侵入，受 Hermes 治理层约束 |
| **二次开发** | fork 后改造，抽取其组件并入 `src/hermes` | 需自己承接其许可与维护 |
| **参考借鉴** | 只学习其架构/prompt/评测方法，不引入代码 | 无许可负担 |

筛选门槛：① 与 Bugcrowd（黑盒 web 为主）场景相关；② 开源可得；③ 能映射到 Hermes 某节点；④ 许可可用（AGPL/专有 EULA 单独标红）。

---

## 1. 分类总览表

### A. 编排 / Autonomous Agent 框架（Hermes 已有受治理编排，主要**参考**，不建议整体替换）

| 仓库 | URL | 能力 | 许可 | 对 Hermes 的建议 |
|---|---|---|---|---|
| Strix | github.com/usestrix/strix | 图式并行多 agent（recon/exploit/post-exploit），Docker 沙箱、HTTP 代理、PoC Python 沙箱、CI 集成 | Apache-2.0 | **参考+局部二开**：其「每个发现都用 PoC 验证」思路与 Hermes 的「最小主动验证+正反对照」同源；可借其工具编排，但保留 Hermes 的审批/复核硬门 |
| PentAGI | github.com/vxcontrol/pentagi | 团队式 agent（Researcher/Developer/Executor/Adviser）、Neo4j 知识图、向量记忆、Docker 隔离、20+ 工具、支持 **DeepSeek** | MIT + 专有 EULA ⚠️ | **参考**：知识图/记忆架构值得借鉴；EULA 条款须先审 |
| hackingBuddyGPT | github.com/ipa-lab/hackingBuddyGPT | 学术级 LLM 驱动测试框架（GitHub Accelerator 2024），结构清晰、易读 | 见仓库 | **参考+二开**：体量小、适合抽取「LLM+shell 循环」最小骨架 |
| CAI (Cybersecurity AI) | github.com/aliasrobotics/cai | REPL 式 pentest 框架、多 provider | 见仓库 | **参考** |
| MANTIS | github.com/insidetrust/mantis | 基于 smolagents 的多 agent + 结构化状态存储 | 见仓库 | **参考**：状态存储设计 |
| Decepticon | github.com/PurpleAILAB/Decepticon | LangChain 多 agent red team | 见仓库 | 参考 |

### B. 侦察 / 攻击面测绘（**Hermes 最缺的能力，建议直接调用**）

| 仓库 | URL | 能力 | 许可 | 复用方式 |
|---|---|---|---|---|
| ProjectDiscovery: subfinder | github.com/projectdiscovery/subfinder | 被动子域枚举 | MIT | **直接调用** |
| ProjectDiscovery: httpx | github.com/projectdiscovery/httpx | HTTP 探测/指纹/存活 | MIT | **直接调用** |
| ProjectDiscovery: katana | github.com/projectdiscovery/katana | 下一代爬虫/端点发现 | MIT | **直接调用** → 喂 Hermes `EndpointInventoryV3` |
| ProjectDiscovery: naabu | github.com/projectdiscovery/naabu | 端口扫描 | MIT | 直接调用（受 program 政策约束）|
| ProjectDiscovery: nuclei | github.com/projectdiscovery/nuclei | 模板化漏洞扫描引擎 + 社区模板库 | MIT | **直接调用**（黑盒检测主力）|
| bbot | github.com/blacklanternsecurity/bbot | 递归 OSINT/攻击面递归发现 | GPL-3.0 ⚠️ | 直接调用（作为外部进程，GPL 不污染）|

### C. MCP 工具服务器（把 B/C 的工具**标准化接入** Hermes Gateway）

| 仓库 | URL | 能力 | 复用方式 |
|---|---|---|---|
| pd-tools-mcp | github.com/intelligent-ears/pd-tools-mcp | 把 ProjectDiscovery 全家桶包成 MCP | **直接调用**（Hermes 作为 MCP client）|
| mcp-for-security | github.com/cyproxio/mcp-for-security | SQLMap/FFUF/NMAP/Masscan… 的 MCP 集合 | 直接调用（挑选合规子集）|
| FuzzingLabs/mcp-security-hub | github.com/FuzzingLabs/mcp-security-hub | Nmap/Ghidra/Nuclei/SQLMap/Hashcat 的 MCP | 参考/挑选 |
| HexStrike AI | github.com/0x4m4/hexstrike-ai | MCP server，聚合 150+ 安全工具 | 参考（面太大，按需挑）|
| nuclei-mcp | github.com/addcontent/nuclei-mcp | 单 Nuclei 的 MCP 封装 | 直接调用（最小）|

### D. 漏洞检测引擎（候选生成，超出 Hermes 现有 4 类固定假设）

| 仓库 | URL | 类型 | 覆盖 | 许可 | 复用方式 |
|---|---|---|---|---|---|
| nuclei（同上）| projectdiscovery/nuclei | 模板化黑盒 | CVE/misconfig/exposure 等海量模板 | MIT | **直接调用** |
| vulnhuntr | github.com/protectai/vulnhuntr | LLM 静态分析（白盒）| Python 源码：LFI/AFO/RCE/XSS/SQLi/SSRF/IDOR，追用户输入→输出调用链 | **AGPL-3.0** ⚠️ | 参考/隔离调用（AGPL 谨慎，勿并入 src）|
| capitalone/VulnHunter | github.com/capitalone/VulnHunter | Agentic「攻击者优先」源码分析 | 源码级 | 见仓库 | 参考 |
| agentic_security | github.com/msoedov/agentic_security | LLM/agent 本身的红队（越狱/fuzz）| 针对 AI 系统 | 见仓库 | 参考（若目标含 LLM 应用）|

### E. 基准 / 评估框架（对应 `docs/15` §10.4「独立 benchmark」——信任输出**前**的门控）

| 仓库 | URL | 内容 | 复用方式 |
|---|---|---|---|
| Cybench | github.com/andyzorigin/cybench | 40 个专业级 CTF，带子任务细粒度评分、CI 化容器 | **直接调用**（做检测率基准）|
| NYU CTF Bench | github.com/NYU-LLM-CTF/NYU_CTF_Bench | 200 个 dockerized CSAW CTF | 直接调用 |
| AutoPenBench | github.com/lucagioacchini/auto-pen-bench | 容器化脆弱环境 + milestone 指标 | 直接调用（最贴近 pentest 流程）|
| D-CIPHER / nyuctf_agents | github.com/NYU-LLM-CTF/nyuctf_agents | 多 agent CTF 框架 | 参考 |
| CAIBench / CyberGym / HackSynth | 见各论文仓库 | 元基准/真实 CVE/自治 pentest 评测 | 参考（选一条主基准即可）|

### F. 平台分类 / 报告（对接 Bugcrowd 终点）

| 仓库 | URL | 内容 | 复用方式 |
|---|---|---|---|
| bugcrowd/vulnerability-rating-taxonomy (VRT) | github.com/bugcrowd/vulnerability-rating-taxonomy | Bugcrowd 官方 VRT，机器可读、映射 CVSS、P1–P5 | **直接调用**（报告分级/去噪）|

---

## 2. 重点仓库调用说明（Top 选型）

### 2.1 nuclei（+ ProjectDiscovery 全家桶）— 直接调用，Hermes 的「真实侦察+黑盒检测」引擎
- **能力**：subfinder→httpx→katana 发现攻击面；nuclei 用模板做无/低交互检测。全 MIT，可安全并入商业/受治理流程。
- **调用**：作为**外部进程**由 Hermes Gateway 调度，或经 `pd-tools-mcp` 以 MCP 方式调用。输出（JSON）→ 归一化为 Hermes `EndpointInventoryV3` / 候选证据。
- **接口点**：Hermes 需写 adapter：`nuclei -json` → `EndpointV3`/`BranchCandidateV3`（保持父运行时对 execution-authority 字段的固定，模型只补 status/rationale）。
- **合规红旗**：nuclei 是**主动扫描**；很多 bounty program 限制/禁止自动化扫描或限速。必须先过 program 的 automation-policy 门（见报告二 N1）。

### 2.2 Strix — 参考 + 局部二开，「PoC 验证」范式
- **能力**：多 agent 并行、HTTP 代理、浏览器利用、PoC Python 沙箱；`strix --target <url|dir>`，支持 Anthropic/OpenAI/本地模型、CI headless。Apache-2.0（可用）。
- **对 Hermes**：**不建议整体替换** Hermes 的治理编排；建议借其「每个候选生成可复现 PoC 再验证」的思路，接进 Hermes 的 DET-03 最小验证节点（但 Hermes 保留逐次审批 + 正反对照 + 报告硬门）。
- **红旗**：其默认「像真黑客一样动态跑代码/利用」与 Hermes 红线（主包不得有任意利用生成）冲突——**只取受控子集**（读多写少、无 RCE/爆破），或将利用能力隔离到 `extensions/`（沿用 `docs/07` 不变量 4）。

### 2.3 PentAGI — 参考，知识图 + 记忆 + DeepSeek
- **能力**：Researcher/Developer/Executor/Adviser 团队、Neo4j+Graphiti 知识图、向量长期记忆、Docker 隔离、原生支持 **DeepSeek**（与 Hermes 当前模型一致）。
- **红旗**：**MIT + 专有 EULA 混合**，商用前须审 EULA。取其「知识图沉淀跨 run 上下文」的架构思想即可。

### 2.4 vulnhuntr — 隔离调用（白盒补充），非黑盒主线
- **能力**：LLM 追 Python 源码「用户输入→输出」调用链，报 LFI/RCE/XSS/SQLi/SSRF/IDOR + PoC + 置信度。
- **定位**：**白盒**，仅当 Bugcrowd program 提供源码/是开源目标时有用；黑盒 web 场景用不上。可作为 Hermes「能力学习闭环」里 source-available gap 的一种 Wheel 参考实现。
- **红旗**：**AGPL-3.0**——若并入 `src/hermes` 会传染整库许可；只以**独立进程/服务**方式隔离调用。

### 2.5 Cybench / AutoPenBench — 直接调用，检测率门控
- **用途**：在把 Hermes 输出用于真实 program **之前**，先在这些基准上跑出可复现的检测率/误报率，回答 `docs/15` §10.4 的「独立 benchmark」。Cybench 有子任务细粒度评分，适合做 Hermes 的回归门。

### 2.6 bugcrowd/VRT — 直接调用，报告分级
- **用途**：把 Hermes 的 `ValidatedFinding` 映射到 Bugcrowd P1–P5 + CVSS，生成**符合平台分类**的报告草稿。机器可读，可直接引入报告生成节点（DET-04）。

---

## 3. 许可与合规红旗速查

| 红旗 | 涉及 | 处置 |
|---|---|---|
| **AGPL-3.0** | vulnhuntr | 勿并入 `src`；只做独立服务隔离调用 |
| **GPL-3.0** | bbot | 作为外部进程调用不传染；勿静态链接/并入 |
| **MIT + 专有 EULA** | PentAGI | 商用前审 EULA；优先只参考架构 |
| **未标 LICENSE** | 多数 agent 框架 | 采用前必须确认；无 LICENSE = 默认保留全部权利，不可直接用 |
| **主动扫描/利用** | nuclei / Strix / mcp-for-security(SQLMap 等) | 只在授权 program + 遵守其 automation policy + 限速；利用类能力隔离到 `extensions/` |

---

## 4. 给 Hermes 的最小可行选型（MVP 二开建议）

> 原则：**能力借外部工具，治理留在 Hermes**。Hermes 的独特价值是受策略治理的编排 + 审批/复核硬门 + 学习恢复闭环，不是又一个自治黑客。

1. **侦察/攻击面**：直接调用 ProjectDiscovery（subfinder/httpx/katana/nuclei），经 `pd-tools-mcp` 接入 Gateway → 归一化为 `EndpointInventoryV3`。
2. **候选生成**：nuclei 模板（黑盒）为主 + Hermes 多领域专家（保持 candidate/blocked/inconclusive 分离）。
3. **验证范式**：参考 Strix 的 PoC 思路，接 Hermes DET-03（读多写少、逐次审批）。
4. **报告**：引入 bugcrowd/VRT 做分级 + CVSS，Hermes DET-04 硬门重验后产出**草稿**（提交=人工）。
5. **门控**：Cybench/AutoPenBench 做检测率基准（`docs/15` §10.4），未达门不上真实 program。
6. **红线**：利用类能力（Strix/SQLMap 等）隔离到 `extensions/`；每个 program 的 automation policy 作为硬前置门（报告二 N1）。

---

## 附：来源

- 综述/清单：[awesome-ai-pentest](https://github.com/insidetrust/awesome-ai-pentest)、[awesome-ai-security-tools](https://github.com/scadastrangelove/awesome-ai-security-tools)、[Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection)、[awesome-cyber-security-mcp](https://github.com/MorDavid/awesome-cyber-security-mcp)
- Agent 框架：[Strix](https://github.com/usestrix/strix)、[PentAGI](https://github.com/vxcontrol/pentagi)、[hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT)、[CAI](https://github.com/aliasrobotics/cai)、[MANTIS](https://github.com/insidetrust/mantis)
- 侦察/检测：[ProjectDiscovery](https://github.com/projectdiscovery)、[nuclei](https://github.com/projectdiscovery/nuclei)、[bbot](https://github.com/blacklanternsecurity/bbot)、[vulnhuntr](https://github.com/protectai/vulnhuntr)、[capitalone/VulnHunter](https://github.com/capitalone/VulnHunter)
- MCP：[pd-tools-mcp](https://github.com/intelligent-ears/pd-tools-mcp)、[mcp-for-security](https://github.com/cyproxio/mcp-for-security)、[mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub)、[HexStrike](https://github.com/0x4m4/hexstrike-ai)
- 基准：[Cybench](https://github.com/andyzorigin/cybench)、[NYU CTF Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench)、[AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench)
- 平台：[Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy)、[Bugcrowd Docs](https://docs.bugcrowd.com/)
