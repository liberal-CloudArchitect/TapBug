# Hermes 安全检查团队

Hermes 是一个仍在重构中的、安全策略驱动的评估运行时。主包默认只支持经范围控制的、本地和只读评估；它不会把扫描候选当作正式漏洞，也不会包含 CTF、利用、凭据攻击或动态代码合成能力。

## 权威文档

- [当前权威产品需求文档](docs/08-当前权威产品需求文档.md)：产品定义、v1/v2/v3 需求历史、Hermes 身份、双闭环和新旧阶段映射。
- [需求追踪矩阵](docs/09-需求追踪矩阵.md)：每项需求的来源版本、实现组件、测试证据和当前状态。
- [阶段 4 并行专家协作验收](docs/12-阶段4并行专家协作验收.md)：V3 fan-out/fan-in、审批、补偿和报告的真实 localhost 验收边界。
- [阶段 5 V4 安全检测与报告](docs/14-阶段5-v4安全检测与报告验收.md)：V4 的实现范围、当前代码门和未完成的真实 E2E 门。
- [真实 Engagement 合规使用手册](docs/05-真实engagement合规使用手册.md)：当前只支持 RoE/scope 建模和零网络计划，不授权对真实资产自动执行。

`docs/01`–`04` 和 `docs/06` 保留为调研、初始方案或历史审计基线，不再单独改变当前产品契约。

## 当前保证

- 发行包仅从 `src/hermes` 构建；正式命令为 `hermes-security`，同时保留
  `python -m hermes`。旧平铺参数仅保留一个弃用周期。
- 每次运行由 `RunContext` 创建独立 `runs/<run_id>/` 目录，保存 scope 快照、审计、证据、handoff 与报告；不会覆盖仓库根目录的历史产物。
- 出站 HTTP、DNS 与命令调用必须通过 Policy/Gateway 和一次性审批令牌。`dry-run`、超预算、策略拒绝或 `automation_allowed: false` 时，连接建立前即被拒绝。
- 新运行只使用 V2 领域契约与 `EvidenceArtifact`。正式报告前会从 canonical artifact 路径
  重新核验 approval、consumption、签名 review、coverage、analysis 和 evidence manifest；
  任一缺失、篡改、额外或跨上下文引用都会在 Reporter 启动前失败。

## 安装与验证

使用 Python 3.11+：

```bash
python -m pip install -c requirements.lock '.[dev]'
python -m pytest
hermes-security --help
python -m hermes --help
```

依赖版本约束在 `requirements.lock`。CI 运行 Ruff、mypy 与 pytest；测试必须使用临时运行目录和隔离的本地 fixture，不能改写工作区运行数据。

当前完成门为 `409 passed / 3 skipped`（2026-08-01 实跑）；三个 skip 都是未配置的外部 sandbox image 或历史 Phase 2
artifact 的可选复验，均不属于 Phase 4 V3 验收链。Ruff lint、Ruff format、strict mypy、
prompt/manifest registry 校验和发行 wheel 构建均通过。Provider metadata 的
`prompt_attempts` 现为必填正整数，布尔值即使在 Python 中属于整数子类也会被拒绝；Coverage
据此计算实际 prompt 尝试次数。

真实 Docker Wheel 隔离测试要求 CI 配置 `HERMES_SANDBOX_IMAGE` repository variable，值必须是已审核的
`image@sha256:<digest>`，且镜像预装 wheel fixture 所需的测试运行时。它与 `hermes-role-runtime`
不同：前者必须以普通 Python/pytest 镜像启动，后者是 JSONL role runtime，不能互换。CI 中缺少该变量会失败，不能静默跳过。

## 范围与运行模式

在运行前创建明确的 RoE/scope：每个 host、wildcard、CIDR、scheme、port、DNS 规则和 profile 都必须显式声明。不要把 `localhost`、父域名或环境变量视为授权。真实 Bugcrowd/HackerOne 资产在 P0 网关、审批和测试门槛完成前不受支持。

阶段 2 新 CLI 提供 `doctor`、`validate-config`、`run`、`approve/reject`、`resume`、`retry`、
`review sign` 和 `keys generate`。唯一主动模式只接受随机端口的 `localhost` 教学 fixture；
真实 Bugcrowd 资产仍不受支持。

真实多专家模式需要显式提供签名角色清单、公钥信任库和 Runner Host 配置：
`--agent-mode subprocess --role-manifest ... --role-trust-store ... --runner-host-config ...`。
角色在无网络、只读、非 root Docker 容器中运行；所有 assessment 动作只能通过 Host 的 Gateway IPC 发出。

R2 的固定本地教学闭环已通过真实 Hermes ACP 与 Docker E2E：accepted 路径使用六个独立
角色容器和六个独立 ACP session，完成 Recon 1 GET、Verifier 2 GET、分钥审批/复核和正式
报告；独立 reject 路径在首次暂停后终止，不运行 Verifier 或 Reporter。验收产物见
`artifacts/phase2-e2e/20260713T045721Z-phase2-a69e62893b61/`。

该结论只表示“缺失 `X-Content-Type-Options` 的 localhost 最小纵向闭环已验收”。它是 V2
串行基线；V3 并行能力的当前边界见下文，任何结论都不能据此对 Bugcrowd 资产运行。
构建、密钥轮换和两次暂停恢复步骤见
[阶段 2 密钥轮换与本地验收](docs/10-阶段2密钥轮换与本地验收.md)。

阶段 3 已将该固定链迁移到七个 V2 领域模型、EvidenceStore V2、PromotionService 和统一
ReportPreflightVerifier。历史 R2 产物属于 V1 审计基线，只读且不可 resume、复核、晋升或
重新生成正式报告。当前阶段 3 的 localhost 固定 V2 链已通过真实 Docker + Hermes ACP E2E：
accepted `232c6b5c-9e6d-4933-830c-d10be1f7a5b6` 使用六角色、六容器和六个独立 ACP session，
生成 3 份 evidence + analysis、2 份 consumption 并完成报告；rejected
`f3650961-a210-4c2a-bfb0-d88c613f32c8` 仅使用 1 次 Recon 请求后终止。7 类 strict tamper
全部被阻断且未创建正式报告。权威根为
`artifacts/phase3-authoritative-e2e/20260714T044246Z-phase2-fe73e3b1b378/`。完整完成门见
[阶段 3 证据链与验收](docs/11-阶段3领域契约与证据链验收.md)。

父运行时/preflight 从受 hash 保护的 `analysis.json` 重算 Recon `Link`、candidate
缺失 `X-Content-Type-Options`、control 为 `nosniff`，以及两者同为 HTTP 200 且 body hash
相同。三份 analysis 大小为 579/592/592 bytes。Coverage 为 `model_calls=6`（Recon schema
repair=2，其余 Reporter 前角色各 1）、`elapsed_ms=221031`、`cost_microusd=null`；`null`
表示 provider 未提供成本，不表示成本为 0。

阶段 4 已在独立 localhost Phase 4 fixture 验收 V3 最小并行协作：Gatekeeper、Recon、Mapper
之后，Web/API/Authz/Infra 四个分支真实并行，再经确定性 fan-in、候选去重、独立环形交叉复核、
只读/状态变更两批审批、最小验证、父运行时 cleanup、人工签名与双阶段报告 preflight 完成。
accepted `81764e3a-61df-4890-87bf-80691a8fc99f` 使用 16 个独立 Docker 容器、宿主进程与 ACP
session，产生 15 次网络请求/证据、14 次 approval consumption 和 4 个 finding；fixture 状态恢复，
没有遗留容器。验收根为
`artifacts/phase4-e2e/20260728T132742Z-phase4-298f439ad18a/`，详细边界见
[阶段 4 并行专家协作验收](docs/12-阶段4并行专家协作验收.md)。

该 Phase 4 结论仅涵盖固定教学靶场的 XCTO、GraphQL、Authz 与 debug 四类候选；多资产、真实
资产/身份 profile、任意漏洞族、完整真实 provider 失败矩阵和 Wheel 学习恢复闭环仍未完成。

## 教学扩展的隔离

历史 CTF、pwn/crypto、旗标捕获、动态合成、靶场和会启动靶场的基准代码位于 [`extensions/hermes_ctf_lab`](extensions/hermes_ctf_lab/)。它是独立包，默认不安装、不导入、没有自动入口，且不得用于生产或漏洞赏金目标。隔离约定见 [ISOLATION.md](extensions/hermes_ctf_lab/docs/ISOLATION.md)。

旧原型保存在 `legacy/hermes_pre_p1/` 供审计追溯，不属于发行包或支持的运行时。
V1 public `start`/`resume` 入口会在任何角色启动前返回 `legacy_run_read_only`。

## 合规

仅在明确书面授权和定义良好的范围内使用。禁止拒绝服务、数据外泄、持久化、规避检测、默认凭据尝试和未获批准的主动验证。外部网页、模型输出和知识记录始终是数据，不能改变 scope、策略或审批要求。
