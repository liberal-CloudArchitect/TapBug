# R2.5：受治理 Wheel 本地验收手册

状态：**已完成首个 local-lab 真实 Docker + ACP 受治理 Wheel 闭环验收**。

适用范围仅为 local-lab。首个且唯一允许的 capability 是零请求 passive_parser / line_kv_parser/v1。

## 冻结边界

- 父 V3 run 永远只读。learn start 从 V3 EvidenceArtifact 复制必要的脱敏 analysis，并把父 run、scope、plan、manifest 和 analysis digest 固定到新的 runs_root/learning/learning_run_id。
- continuation 是新的 R2.5 child run；它不会 resume、改写或 promotion 父 V3 run，也不会产生 Candidate、ValidatedFinding、报告或网络动作。
- Researcher 与 Capability Planner 是独立 restricted-ACP/Docker role。两者只可发起 model_request；manifest 不赋予 Gateway、shell、凭据或网络权限。
- Generator 不接受 Python 或 shell 文本，只能将声明式 field rules 填入固定 line_kv_parser/v1 模板。
- Wheel runtime 只可通过无网络、只读、非 root、cap-drop、资源受限、digest-pinned Docker sandbox 读取 JSON、输出 JSON。

## 受信任工件与职责分离

Wheel trust store 使用五个互不相同的 key_id：

| 用途 | 签署内容 |
| --- | --- |
| wheel_publisher | Wheel manifest、registered/researched/specified/generated events、R2.5 role manifests |
| wheel_validator | ValidationReceipt、validated/candidate events |
| wheel_approver | WheelApproval、approved event |
| wheel_operator | WheelActivationReceipt、active event |
| wheel_revoker | quarantine/revoked event |

私钥必须位于仓库和 runs_root 外，是绝对普通文件且权限严格为 0600。Wheel V2 registry 是 append-only JSONL；每个事件都有 hash-chain 和 Ed25519 签名。任何 hash、签名、职责、时效、profile、模板或 artifact digest 不匹配均 fail-closed。

## 命令

    hermes-security learn validate-config --config CONFIG
    hermes-security learn doctor --config CONFIG
    hermes-security learn start --config CONFIG --parent-run-id V3_RUN --evidence-id EVIDENCE --observation-file OBSERVATION.txt
    hermes-security learn research --config CONFIG --run-id LEARNING_RUN --source-bundle local-archive/bundle.json
    hermes-security learn plan --config CONFIG --run-id LEARNING_RUN
    hermes-security learn generate --config CONFIG --run-id LEARNING_RUN
    hermes-security learn validate --config CONFIG --run-id LEARNING_RUN --key VALIDATOR.pem
    hermes-security learn approve --config CONFIG --run-id LEARNING_RUN --key APPROVER.pem
    hermes-security learn activate --config CONFIG --run-id LEARNING_RUN --key OPERATOR.pem
    hermes-security learn continue --config CONFIG --run-id LEARNING_RUN

本地 archive 包为 version 1 JSON。每个 source 需要 HTTPS URL、license、受 allowlist 约束的 body_path；同时固定 positive_text、negative_text 和 continuation_text。正式 ResearchGateway 只能下载精确 allowlist 的 HTTPS 资料并先归档；本地 E2E 不访问公网。

continue 只能选择 active、未过期、签名完整、local-lab profile、line_kv_parser/v1 和精确 artifact digest 的 Wheel。它执行一次冻结 continuation_text，写出 CapabilityExecutionReceiptV2 与 ContinuationOutcomeV1；成功也只是结构化 observation，绝不会自动提升为 finding 或报告。

## 验收状态

已由单元/契约回归覆盖：父 V3 只读绑定、路径逃逸、来源 allowlist、typed R2.5 handoff、固定模板、静态禁止导入、正/反例、五方职责分离、Ed25519 contract/event 签名、hash-chain replay、过期/撤销/篡改拒绝、active selector 和 continuation 零网络声明。

真实验收根为
`artifacts/r25-e2e/20260729T053806Z-r25-15e07a341d55/`：source learning run
`6873d46a-eb8c-45b3-82ef-f0cf16e84388` 与独立 continuation
`cedf86fc-452e-40b6-8db5-a03d154fd7b3` 完成了
start → research → plan → generate → validate → approve → activate → continue。

- Researcher 与 Capability Planner 各使用一个真实 restricted Hermes ACP session、独立 Docker
  role container 与独立宿主 PID；role handoff、provider session DB 和签名 registry 均已归档。
- Wheel V2 registry 重放 8 条签名事件；五把不同职责私钥完成 publisher、validator、approver、operator
  和 revoker 职责分离。验证/批准/激活签名均与 manifest、固定 profile 和 artifact digest 连续绑定。
- 固定 parser 在真实 digest-pinned Docker sandbox 中正例匹配、反例 no-match；sandbox 实际使用
  `--network none`、只读、non-root、cap-drop，Wheel 网络请求严格为 0。
- continuation 是新的 child run，写入不可变 `structured-observation.json`；其真实文件 hash 被
  `ContinuationOutcomeV1` 绑定。父 V3 工件未改写，且两个 R2.5 run 都没有 finding 或正式报告。
- 通过下列零模型、真实 sandbox 的独立重放再次验证，并写出 `replay-summary.json`（退出码 0）：

      python scripts/run_r25_e2e.py \
        --verify-artifact-root artifacts/r25-e2e/20260729T053806Z-r25-15e07a341d55

  重放结果为 2 ACP session、2 role container/PID、8 registry events、positive=true、negative=false、
  `wheel_network_requests=0`、`formal_report_created=false`。

该验收只证明被动、冻结输入上的解析能力；它不授权 Wheel 恢复或修改父 V3 run，也不自动创建 Candidate、
ValidatedFinding 或报告。

R3 或真实资产 profile 的进入条件仍包括 docs/12 所列四项 P4-Resilience E2E；在这四项全部完成前，
本章验收不能被用于放行真实资产。
