# WebAuthn 仪式模拟工作台（Ceremony Lab）

一个完全运行在本地的 WebAuthn 注册 / 认证仪式（ceremony）模拟工作台。后端签发
**一次性、带过期时间**的 challenge，保存凭据与签名计数器；前端用一个**纯软件实现的
测试 authenticator** 重放不同客户端行为，并逐步展示每一步的输入 / 输出。

- 不连接任何真实身份平台（无 FIDO 元数据服务、无企业 IdP）
- 不使用任何外部数据库（凭据与 challenge 仅存于服务端内存）
- 所有二进制字段统一使用 **base64url 无填充**编码
- 可导出**不含私钥**的仪式记录 JSON，并重新导入由服务端独立复核

技术栈：TypeScript · React 18 · Express · Vite。

---

## 快速开始

```bash
npm install

# 同时启动 API(8787) 与 Vite 开发服务器(5173)，/api 自动代理
npm run dev
# 打开 http://localhost:5173

# 或者：类型检查 + 构建前端，再由 Express 单端口托管
npm run build
npm start          # http://localhost:8787 同时提供 API 与静态资源
```

### 环境变量（服务端 RP 策略）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `8787` | API / 生产静态端口 |
| `RP_ID` | `localhost` | 服务端信任的 RP ID（客户端无法覆盖） |
| `RP_NAME` | `WebAuthn Ceremony Lab` | RP 显示名 |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,http://[::1]:5173` | 精确 origin 白名单（逗号分隔，无通配后缀规则） |

---

## 运行测试

```bash
npm run typecheck           # server + web 两套 tsconfig
npx tsx scripts/e2e.ts      # 35 项 HTTP 端到端场景（先启动服务端）
npx tsx scripts/device.ts   # 12 项软件 authenticator 单元行为
```

---

## 架构

```
┌────────────────────────── 浏览器 (src/) ───────────────────────────┐
│  SettingsPanel 场景预设/参数注入                                    │
│        ├─► runner.ts 逐步记录(RP/设备/浏览器) ──► api.ts /api/*     │
│  StepsPanel ◄ 每一步输入输出                                        │
│  ConcurrencyPanel 两个页面并发消费同一 challenge                    │
│  RecordsPanel  导出 / 导入仪式记录                                  │
│                                                                    │
│  software authenticator (shared/authenticator.ts)                  │
│   · ES256 P-256 (WebCrypto, non-extractable 私钥)                   │
│   · 可注入时钟 / UP / UV / resident / 失败注入                      │
└───────────────────────────────────────┬────────────────────────────┘
                                         │ base64url JSON
┌───────────────────────────────────────▼──────────── 服务端 ─────────┐
│  Express (server/)                                                  │
│   app.ts   HTTP 路由、RP 策略、原子消费、事件日志、静态托管          │
│   store.ts 内存：challenge 表 + 凭据表（无外部 DB）                 │
│   verify.ts §7.1/§7.2 验证链 + 记录复核                            │
└────────────────────────────────────────────────────────────────────┘

shared/ : bytes(base64url) · cbor(最小 CBOR) · webauthn(COSE/authData/ES256)
          · authenticator(软件设备) · protocol(线网与记录类型)
```

### Challenge 生命周期（一次性 + TTL）

1. `POST /api/register/begin` 或 `/api/auth/begin` 生成 32 字节随机 challenge，
   `expiresAt = now + timeout`（限制在 5s–300s）。
2. challenge 在内存中状态为 `pending`。
3. 第一次 `finish` **在任何密码学校验之前**原子地把它置为 `consumed`
   （事件循环单线程 + 状态翻转），记录 `consumedBy`（客户端标签）与最终裁决。
4. 之后任何重复提交都得到 `challenge-consumed`，并附带赢家信息。
5. 超过 `expiresAt` 的 pending challenge 在下次访问或每 5 秒一次的清扫中变为
   `expired`，提交得到 `challenge-expired`。
6. 设备端失败（取消 / 超时 / 用户缺席 / 未找到凭据）**不会**到达服务端，
   因此 challenge 保持 `pending` 直至过期——与真实浏览器一致。

---

## 严格区分的概念

| 概念 | 在哪里体现 |
| --- | --- |
| **origin** | clientDataJSON.origin 必须精确命中 `ALLOWED_ORIGINS`；`crossOrigin=true` 单独拒绝 |
| **RP ID** | 服务端固定 `RP_ID`；设备对“有效 RP ID”做 SHA-256 写入 authData，服务端重算并逐字节比对 |
| **user verification (UV)** | options.userVerification=required 时强制要求 authData 的 UV 标志位 |
| **resident key** | residentKey requirement 与 BE/BS 标志位双向校验；可走空 allowCredentials 的 discoverable 登录 |
| **attestation 偏好** | options.attestation=direct 时拒绝 fmt=none；支持 fmt=none 与 self packed（ES256，服务端验签） |

### 软件 authenticator 支持的注入

- ES256（ECDSA P-256），私钥 `extractable:false`，仅存页面内存
- 有效 origin / RP ID 覆盖、crossOrigin
- UP / UV / resident（BE/BS）标志位
- attestation 格式：`none`、`packed`（自证明）
- `failure: cancel | timeout`、可调延迟、AbortSignal
- 签名损坏（翻转 DER 末字节）
- 复用已有 credential id
- 签名计数器：时钟派生（uint32 环绕）或强制精确值
- **可注入时钟**：偏移秒数（负数回拨）

---

## 场景与可解释终态

| 场景 | 终态 / 错误码 |
| --- | --- |
| 正常注册 / 认证 | `200`，凭据入库、计数器更新 |
| 取消 | 设备抛 `NotAllowedError`，challenge 留 `pending` |
| 超时 | 设备抛 `TimeoutError`；或等待自然 TTL → `challenge-expired` |
| 两个页面同时完成同一 challenge | 恰一个成功，另一个 `challenge-consumed`（附赢家） |
| 错误 origin | `bad-origin`（origin 不在白名单）/ `crossOrigin` 标记 |
| 错误 RP ID | `bad-rpid`（rpIdHash 不一致） |
| 签名失败 | `bad-signature`（ES256 验签失败） |
| UV required 未验证 | `user-not-verified` |
| 用户缺席 | 设备 `NotAllowedError`，或服务端 `user-absent`（UP=0） |
| 重复 credential id | 设备 `InvalidStateError`；服务端 `duplicate-credential` / `credential-exists` |
| 未知凭据 | `unknown-credential` |
| 计数器回退 | HTTP 仍 `200` 但 `cloneWarning:true`，凭据标记 `cloneDetected`，计数器**不回退** |
| uint32 环绕（时钟回拨） | 同上（突增 > 2³¹−1 判为异常环绕） |

> 计数器回退按 WebAuthn 规范处理：签名密码学上仍然成立，但这是克隆设备的强信号，
> 因此结果带克隆告警、服务端冻结计数器、不采用更小（或环绕）的值。

---

## 仪式记录的导出 / 导入

每次仪式结束后可导出 `webauthn-ceremony-lab/record`（v1）JSON，包含：

- RP 与期望 origin
- begin 返回的完整 options（含 challenge、选择器、TTL）
- 设备原始 response：`clientDataJSON`、`attestationObject` 或
  `authenticatorData`、`signature`、标志位（均为 base64url）
- 当时的服务端裁决与场景备注

**记录永远不含私钥**：attestation 里只有公钥 COSE_Key，断言里只有签名；设备私钥是
non-extractable 的 WebCrypto 句柄，从不离开内存、从不被序列化。

导入后由 `POST /api/records/check` 在**不消费任何 challenge**的前提下重跑完整校验链。
对认证记录还会用服务端凭据的当前计数器复核——一条历史记录在凭据继续使用后再导入，
计数器检查会自然报克隆提示，演示了独立复核的效果。

---

## 自行实现的最小原语（无第三方 WebAuthn 库）

- `shared/bytes.ts`：base64url（无填充；读取容忍标准字母表 / padding）、UTF-8、常量时间比较
- `shared/cbor.ts`：确定性 CBOR 编解码（uint / 负整数 / bytes / text / array / map / bool / null，
  支持整数与文本两类 map 键）
- `shared/webauthn.ts`：COSE EC2(ES256) 密钥、authData / attestedCredentialData 解析、
  rpIdHash、clientDataJSON、DER↔raw ECDSA、ES256 验签
