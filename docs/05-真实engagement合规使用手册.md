# 真实 Engagement 合规使用手册（Bugcrowd 等）

> 文档状态：现行。适用于 PRD 1.6（2026-07-29）。  
> 当前产品门：Hermes 已验收 localhost 上的真实 ACP/Docker 多专家、pinned transport、批准后的最小主动 PoC 和受治理 Wheel 被动解析链；**仍不支持对真实 Bugcrowd/HackerOne 资产自动执行检测**。本手册把真实 engagement 限定为 RoE 整理、scope 建模、零网络计划和人工复核。

## 1. 使用红线

1. 只能使用当前 Engagement Brief 明确授权的资产、scheme、port、账号和测试方式。
2. 不得根据父域、自动发现、DNS 结果或模型推测扩大 scope。
3. 自动化、限速、请求头、测试账号、禁测项、数据处理和披露条款必须逐项记录。
4. 禁止 DoS、数据外泄、持久化、绕过检测、未批准凭据使用和未批准主动验证。
5. `extensions/hermes_ctf_lab` 及其 RCE、夺旗、pwn/crypto、合成和靶场功能永远不得指向真实 engagement。
6. hook 只是宿主工具的外围辅助；Python 运行时的唯一授权边界是 Policy/Gateway。

## 2. 在平台上收集 RoE

在建立 Hermes scope 之前，由人工阅读当前项目页面并保存一份带日期的授权摘要：

- 项目名称和 Brief URL；
- 查看日期和适用的规则版本；
- 精确 in-scope 资产，以及 wildcard 是否明确允许；
- 明确 out-of-scope 资产和第三方服务；
- 是否允许自动化、每秒请求数、总请求和测试时段；
- 允许的 scheme/port；
- 是否要求平台测试账号或识别请求头；
- 禁止的测试类型；
- 敏感数据的停止、保留、脱敏和删除要求；
- Safe Harbor 和协同披露条款。

平台规则可能改变。每次新 run 之前都要重新确认，不能重用旧项目的 scope 文件作为新授权证明。

## 3. 用当前 Schema 建立 Scope

复制当前模板：

```bash
cp templates/scope-bugbounty.yaml scope.yaml
```

`ScopePolicy` 是 fail-closed 的，只接受明确字段。每条规则必须声明：

- `host`：精确域名/IP/CIDR，或 Brief 明确允许的左侧 `*.example.com`；
- `schemes`：仅 `http`/`https`；
- `ports`：明确允许的端口；
- `allow_dns`：域名规则需要 DNS 时显式开启；
- `allow_private`：真实资产保持 `false`，仅精确本地回环靶场允许 `true`；
- `profile`：必须与顶层 profile 一致。

对真实项目建立计划时，保持：

```yaml
automation_allowed: false
dry_run: true
allowed_commands: []
```

不要把真实凭据、Cookie、API key、平台 token 或原始敏感响应写入 scope、prompt、agent handoff 或知识库。

## 4. 当前允许的 Hermes 操作

### 4.1 环境前置

先把项目安装到当前受支持的 Python 3.11+ 环境：

```bash
python -m pip install -c requirements.lock '.[dev]'
python -m hermes --help
```

`excavator` 只是历史环境名，不是必需前提；无论使用何种环境，都必须显式安装项目和开发依赖。

### 4.2 校验真实项目的 Scope Schema（不连接目标）

当前实现已经注入基于 `socket.getaddrinfo` 的系统 resolver，并由 PolicyEngine 校验、由 pinned
transport 使用固定 IP 连接。但产品验收只允许 `localhost` local-lab；真实域名会在纵向工作流入口
fail-closed。在完成独立真实域名治理、部署和项目级 RoE 验收前，只做无副作用 schema/config 校验，
不对真实资产运行 workflow：

```bash
python -c "from pathlib import Path; from hermes.orchestrator import load_scope_policy; load_scope_policy(Path('scope.yaml')); print('scope schema valid')"
```

这只证明 YAML 符合当前 `ScopePolicy`，不证明 Brief 录入正确、目标可连接或已获得自动化授权。

### 4.3 在本地回环靶场生成零网络计划

仓库默认 `scope.yaml` 只允许 `http://127.0.0.1:3000`。对该本地回环规则可执行：

```bash
python -m hermes \
  --scope scope.yaml \
  --runs-root runs \
  --target http://127.0.0.1:3000/
```

预期结果：

- 创建 `runs/<run_id>/scope.json`；
- 创建 `runs/<run_id>/plan/run-plan.json`；
- 验证 target/scheme/port/profile 是否符合 scope；
- 输出 `network: disabled`；
- 不执行侦察、爬取、扫描、登录、探针或利用。

旧平铺参数兼容模式仍是 plan-only。新的 `hermes-security run` 只允许严格 local-lab，并会执行
已验收的真实 Docker/ACP 最小链；`approve`、`resume`、`review sign` 只可消费该 local-lab run
的签名工件。该验收不授权把 target、scope profile 或 transport 替换成真实资产；这需要独立的真实
域名治理、部署和项目级 RoE 验收。

## 5. 当前禁止的真实项目操作

以下能力在完成相应阶段验收前不得用于真实资产：

| 能力 | 当前决议 | 解除限制的最低门槛 |
|---|---|---|
| subprocess 多专家模式 | 仅允许已验收的 localhost 教学链；禁止作为真实资产评估能力声称 | 真实域名 profile、部署控制面、平台 RoE 和独立真实资产验收 |
| 自动化侦察/扫描 | 禁止 | R1 部署 E2E、项目明确允许自动化、预算/限速与 coverage 验收 |
| 带 Cookie/Authorization 的请求 | 禁止 | 受控 Secret Broker、认证动作分类、逐次审批和脱敏证据 E2E |
| POST/PUT/PATCH/DELETE、登录、注入探针 | 禁止 | 真实项目专用的外部人工审批、暂停/恢复、正反对照验证、证据链与部署 E2E；localhost PoC 验收不移植到真实资产 |
| 自动生成 Wheel 在目标上首次运行 | 禁止 | 除 R2.5 Docker/签名/registry 外，还需真实项目 RoE、受控身份与独立真实资产验收；当前 Wheel 只能解析冻结脱敏本地输入 |

## 6. 从候选到平台提交

Hermes 未来产生的任何 Candidate 都只是调查线索。提交前必须由人工：

1. 确认资产、时间和动作均在当前 RoE 内。
2. 核查正向/反向对照，排除公开 API、SPA fallback、登录页、缓存和模板误报。
3. 以最小必要动作确认影响；触及意外敏感数据立即停止。
4. 对请求、响应、帐号、token、个人数据和内部识别符脱敏。
5. 人工校对影响、复现、修复建议、VRT 和 CVSS。
6. 使用平台当前表单提交并遵循协同披露。

“格式对齐 VRT”、“Hermes 内部 validated”和“平台可提交/可接受”不是同一状态。最终提交责任必须由研究员承担。

## 7. 事故和停止条件

出现以下任一情况时立即停止当前活动，保全脱敏审计记录，不要自行扩大调查：

- scope 、RoE 或自动化权限存疑；
- DNS/重定向到未授权或第三方资产；
- 意外的状态变更、账户锁定或可用性影响；
- 出现真实用户数据、凭据或超出最小 PoC 的数据；
- 审批、证据、日志或 Wheel 完整性校验失败；
- 超出限速、请求、时间或成本预算。

## 8. 与开发阶段的关系

当前支持程度以 [`08-当前权威产品需求文档.md`](08-当前权威产品需求文档.md) 和 [`09-需求追踪矩阵.md`](09-需求追踪矩阵.md) 为准。

- R0/R1：控制面有单元/契约证据，部署 E2E 仍有缺口。
- R2：固定 localhost 教学 fixture 的六角色最小纵向闭环已验收；并行、更多漏洞类型和真实资产 profile 未验收。
- R2.5：固定 `passive_parser` 已通过真实 ACP/Docker/signed-registry child continuation 验收；它不恢复或改写父 V3 run，也不产生 finding/报告。
- R3：只有最小质量基线，不代表真实赏金发现率。
