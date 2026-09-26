# WebAuthn 仪式模拟工作台

浏览器内的 WebAuthn 注册 / 认证仪式模拟器：用**软件测试 authenticator** 重放各种客户端行为，
前端逐步展示每个仪式的输入输出，后端签发一次性 challenge、保存凭据与签名计数器。
**不连接任何真实身份平台或外部数据库**——服务端状态全部在内存中，重启即清空。

## 技术栈

TypeScript · React · Express · Vite（npm workspaces monorepo）

```
packages/
  shared/   环境无关核心：base64url、CBOR、authData、软件 authenticator、
            服务端校验逻辑、仪式记录离线复检（浏览器与 Node 复用同一份代码）
  server/   Express：challenge 签发/一次性消费/过期/取消，凭据与计数器内存存储
  web/      React + Vite：仪式配置、authenticator 面板、场景触发、步骤时间线、导出/导入
```

## 运行

```bash
npm install
npm run dev        # 服务端 :8787 + Vite 开发服务器 :5173（/api 代理到 8787）
```

打开 http://localhost:5173 。生产模式：

```bash
npm run build && npm start   # 服务端直接托管 web/dist，单端口 8787
```

测试与类型检查：

```bash
npm test           # vitest：33 个用例（含并发消费、克隆告警、重复 credential id 等）
npm run typecheck
```

## 严格区分的维度

| 维度 | 实现 |
| --- | --- |
| origin | 服务端持有允许列表（`ALLOWED_ORIGINS`），与 clientDataJSON.origin 比对；工作台可让客户端故意谎报 |
| RP ID | 服务端权威 rpId（`RP_ID`），校验 `authData.rpIdHash == SHA-256(rpId)`；可让 authenticator 使用错误 rpId |
| user verification | `required/preferred/discouraged`；required 时服务端强制 UV 标志位，authenticator 可配置"支持 UV / 用户是否通过" |
| resident key | `required/preferred/discouraged`；resident 凭据支持无 `allowCredentials` 的 discoverable 认证 |
| attestation | `none`（fmt=none）/ `direct`（packed 自证明，ES256 签名 authData‖clientDataHash） |
| challenge | 一次性（同步原子消费）+ 绝对过期时间（默认 60s，可按仪式配置 250ms–10min） |

所有二进制字段（challenge、credential id、签名、authData、clientDataJSON…）一律
**base64url 无填充**编码。

## 场景与可解释终态

每个仪式终态都带完整检查链（checks），在页面中逐条展示：

| 场景 | 终态 |
| --- | --- |
| 注册 / 认证 | `completed` |
| 取消（确认前取消，再提交） | `cancelled` → 提交得到 `ceremony_cancelled` |
| 超时（TTL 1.2s，延迟提交） | `expired` → 提交得到 `challenge_expired` |
| 并发消费（两页面同一 challenge） | 一个 `completed`，另一个 `challenge_consumed`（HTTP 409） |
| 错误 origin | `failed` / `origin_mismatch` |
| 错误 RP ID | `failed` / `rp_id_mismatch` |
| 签名失败（篡改 1 字节） | `failed` / `bad_signature` |
| 计数器克隆（回退计数器后认证） | `completed_with_clone_warning`，检查链中 `counter.monotonic` 标红 |
| 重复 credential id | `failed` / `duplicate_credential`（authenticator 侧钩子强制复用 id，跳过 excludeCredentials） |
| UV required 但用户未通过 | `failed` / `uv_required` |

## 导出 / 重新导入检查

每条仪式记录可导出为 JSON（**绝不包含私钥材料**，公钥以 base64url 的 x/y 坐标保存）。
"重新导入检查"面板对记录离线重放全部可验证项：

- 结构与版本、所有二进制字段的 base64url 规范性（无填充、重编码一致）
- 步骤中不含私钥材料的扫描
- clientDataJSON 与 options.challenge / origin 的绑定
- `authData.rpIdHash == SHA-256(rpId)`
- 注册：packed 自证明签名重放验证；认证：用记录中的公钥重放验证断言签名

## 测试 authenticator

- ES256（P-256 + SHA-256），签名统一 IEEE P1363（r‖s）
- **可注入时钟**：实时 / 固定 ISO 时间，用于确定性记录
- 可配置 UV 支持与结果、resident key 支持
- 测试钩子：`debugSetCounter`（计数器回退 → 克隆告警）、`debugForceCredentialId`（复用 id → 重复注册）
- 私钥只存在于内存句柄（CryptoKey/KeyObject），任何日志、导出都不包含

## API 摘要

```
GET  /api/config                     服务端 rpId / 允许 origin / 默认 TTL
POST /api/register/options           签发注册 challenge（一次性、带 expiresAt）
POST /api/register/result            校验 attestation，落库凭据与计数器
POST /api/authenticate/options       签发认证 challenge（discoverable 时 allowCredentials 为空）
POST /api/authenticate/result        校验 assertion，推进计数器 / 克隆告警
POST /api/ceremonies/:id/cancel      取消仪式（challenge 作废）
GET  /api/ceremonies                 仪式列表（含终态与检查链）
GET  /api/credentials                凭据库（内存）
POST /api/reset                      清空全部状态
```

环境变量：`PORT`（默认 8787）、`RP_ID`（默认 localhost）、`ALLOWED_ORIGINS`（逗号分隔）。
