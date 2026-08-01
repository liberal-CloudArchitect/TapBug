# Hermes 批测评分卡 · cybench（2026-07-10 11:41:33Z）

**fair-shot 解题率（拿到可用靶时）：3/14 = 21%** ← 真实能力指标
- 在域内（有 target_host）：3/24 = 12%
- 原始（全 43）：3/43 = 7%
- **环境挡住 29 题**（agent 没拿到靶：no_server/build_failed/unsupported_deploy/target_down），不计入 fair-shot · 平均耗时 73s/题

## 按类别

| 类别 | 解出/总 | 解题率 |
|------|--------|--------|
| crypto | 0/14 | 0% |
| forensics | 0/4 | 0% |
| misc | 0/7 | 0% |
| pwn | 1/4 | 25% |
| reverse | 0/8 | 0% |
| web | 2/7 | 29% |

## 按难度

| 难度 | 解出/总 | 解题率 |
|------|--------|--------|
| 0 | 1/6 | 17% |
| 1 | 1/12 | 8% |
| 2 | 0/6 | 0% |
| 3 | 1/11 | 9% |
| 4 | 0/6 | 0% |
| 5 | 0/2 | 0% |

## 类别 × 难度

| 类别 | 难度 | 解出/总 |
|------|------|--------|
| crypto | 1 | 0/4 |
| crypto | 3 | 0/5 |
| crypto | 4 | 0/4 |
| crypto | 5 | 0/1 |
| forensics | 0 | 0/2 |
| forensics | 1 | 0/1 |
| forensics | 2 | 0/1 |
| misc | 1 | 0/4 |
| misc | 2 | 0/1 |
| misc | 3 | 0/1 |
| misc | 5 | 0/1 |
| pwn | 1 | 1/1 |
| pwn | 2 | 0/1 |
| pwn | 3 | 0/1 |
| pwn | 4 | 0/1 |
| reverse | 0 | 0/3 |
| reverse | 1 | 0/1 |
| reverse | 2 | 0/2 |
| reverse | 3 | 0/1 |
| reverse | 4 | 0/1 |
| web | 0 | 1/1 |
| web | 1 | 0/2 |
| web | 2 | 0/1 |
| web | 3 | 1/3 |

## 未解出的错误类型分布

| 类型 | 数量 |
|------|------|
| no_server | 19 |
| build_failed | 9 |
| no_flag | 7 |
| miss | 2 |
| exec_error | 2 |
| unsupported_deploy | 1 |

> 解题率=真实夺旗率（自扩展 agent 现写 exploit + ensemble）。错误类型指导后续投入：
> target_down=靶起不来(环境)、no_flag=方法没打通、exec_error=生成代码报错、needs_tool=缺工具、timeout=超时。