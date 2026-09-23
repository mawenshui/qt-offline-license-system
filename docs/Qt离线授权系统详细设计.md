# Qt 纯软件离线授权系统详细设计

| 属性 | 值 |
| --- | --- |
| 文档版本 | 1.1 |
| 状态 | 设计基线 |
| 目标平台 | Windows、Linux |
| Qt 基线 | Qt 5.12.12，兼容后续 Qt 5/Qt 6 |
| 网络要求 | 签发端、采集端、验证端均可永久离线运行 |
| 密码套件 | Ed25519 + XChaCha20-Poly1305 + Argon2id |

## 1. 文档目的

本文定义一套供 Qt 应用使用的纯软件离线授权系统，覆盖：

- 单台设备授权和批量设备授权。
- CPU、主板、硬盘、机器 ID 等硬件项的单选、多选及阈值匹配。
- 永久授权、固定日期授权、签发后有效时长授权、应用实际运行时长授权和混合授权。
- 根据用户提交的硬件信息生成授权文件。
- 从 CSV、JSON 批量导入多台设备并批量生成授权文件。
- 单个或批量生成永久授权。
- 授权文件读取、验签、解密、展示和审计。
- Windows、Linux 验证端永久离线运行。
- 限期授权的系统时间回拨检测和本地状态防回滚。
- 签发密钥安全存储、备份、轮换和恢复。

本文同时给出协议、数据结构、模块边界、错误码、测试和验收标准，作为后续编码依据。

## 2. 关键术语和安全结论

### 2.1 “密钥”和“授权文件”必须区分

- **签名密钥对**：Ed25519 公私钥。私钥只存在于内部签发端；公钥或根公钥放入 Qt 应用。
- **产品加密密钥**：32 字节对称密钥，用于加密授权载荷。签发端和验证端都需要，因此不能作为防伪安全根。
- **授权文件**：面向某个产品、客户和硬件指纹签发的 `.qtlic` 文件。
- **永久授权**：授权文件中的 `license_mode` 为 `perpetual`，不是重新生成一套签名密钥，也不使用“9999-12-31”伪装永久期限。

用户界面中的“生成密钥”统一显示为“生成授权”，避免把签名私钥误认为客户授权码。

### 2.2 安全根是数字签名，不是解密密钥

验证端必须能够解密授权内容，因此对称解密密钥最终可以被逆向提取。授权文件加密只能隐藏内容，不能防止伪造。

防伪依赖 Ed25519 签名：

- 私钥只在签发端。
- 验证端只需根公钥或签发公钥。
- 修改客户、硬件、期限、功能或密文都会导致验签失败。
- 必须先验签，再解密和使用授权内容。

### 2.3 纯软件永久离线的时间边界

纯软件无法在管理员/root 可控、可恢复整机快照的设备上获得不可篡改的绝对 UTC。系统能实现：

- 检测常规系统时间回拨。
- 防止运行期间冻结系统时间来无限延长授权。
- 通过多副本状态、MAC 和哈希链提高状态回滚成本。
- 保证永久授权完全不依赖系统时间。

系统不能保证抵抗：

- 管理员/root 同时回滚全部状态副本。
- 虚拟机或整机磁盘快照回滚。
- 修改内核计时源。
- 直接补丁掉本地授权判断。

这些限制必须出现在产品安全说明中，不能宣传为“绝对防破解”。

## 3. 范围与非目标

### 3.1 本期范围

- Qt Widgets 签发工具。
- 可脚本化的命令行签发工具。
- 硬件信息采集工具。
- 可嵌入 Qt 应用的 Runtime SDK。
- 离线密钥库。
- 单个、批量授权生成和读取。
- 永久、限期、累计时长、混合授权。
- 纯软件离线时间防回拨。
- Windows、Linux 构建和测试。

### 3.2 非目标

- 在线激活、在线吊销或许可证服务器。
- 账号登录、云端租户管理。
- 抵抗内核级攻击或拥有完整调试权限的高级攻击者。
- 用自研密码算法替代成熟密码库。
- 将客户原始硬件序列号写入授权文件。

## 4. 总体架构

```text
┌──────────────────────┐
│ HardwareCollector    │
│ Windows / Linux      │
└──────────┬───────────┘
           │ hardware.qreq / 手工录入 / CSV / JSON
           ▼
┌──────────────────────────────────────────┐
│ LicenseIssuer                            │
│  单个签发 | 批量签发 | 永久 | 限期       │
│  读取验证 | 模板 | 审计 | 密钥库         │
└──────────┬───────────────────────────────┘
           │ *.qtlic + batch-manifest.json
           ▼
┌──────────────────────────────────────────┐
│ Qt Application + LicenseRuntime          │
│  验签 → 解密 → 产品 → 硬件 → 时间 → 功能 │
└──────────────────────────────────────────┘
```

建议目录：

```text
LicenseSystem/
├── common/                 # 协议、模型、规范化、密码封装
├── runtime/                # 嵌入业务 Qt 应用，无 Widgets 依赖
├── issuer/                 # Qt Widgets 签发工具
├── collector/              # 客户机硬件采集工具
├── cli/                    # 自动化和批量签发 CLI
├── tests/                  # 单元、协议向量、跨平台测试
├── examples/               # Qt 接入示例
└── docs/                   # 协议和运维文档
```

## 5. 功能需求

### 5.1 产品管理

每个产品配置包含：

- `product_id`：稳定、区分大小写的 ASCII 标识。
- `display_name`：界面名称。
- `product_version_scope`：可选版本范围。
- 支持的功能列表及默认功能。
- 根公钥、签发密钥证书列表。
- 产品加密密钥 ID 列表。
- 默认硬件绑定策略。
- 默认授权模板。
- 默认授权输出目录和命名规则。

`product_id` 一经发布不得修改。显示名称可修改，不参与安全判断。

### 5.2 密钥库管理

签发工具必须支持：

- 初始化根签名密钥。
- 生成日常签发密钥，并由根私钥签发证书。
- 生成产品加密密钥。
- 导入、导出加密密钥库。
- 修改密钥库口令。
- 展示公钥指纹、`kid`、创建时间和状态。
- 将密钥标记为 `active`、`retired`、`compromised`。
- 生成只包含公开材料的 Runtime 配置包。
- 生成离线加密备份。
- 禁止将明文私钥写入日志、剪贴板或临时文件。

签名密钥不是按用户生成。默认一个签发密钥签发多个用户授权，每个授权使用独立 `license_id` 和随机加密 nonce。

### 5.3 单个授权生成

签发员可：

1. 选择产品和授权模板。
2. 输入客户 ID、客户名称、订单号和备注。
3. 导入 `.qreq` 或手工输入硬件信息。
4. 选择至少一个绑定槽位。
5. 选择 `all`、`any` 或 `threshold` 匹配规则。
6. 选择授权模式。
7. 选择功能权限。
8. 预览最终载荷。
9. 解锁密钥库并生成 `.qtlic`。
10. 立即执行自验证，验证失败则不输出文件。

### 5.4 多硬件信息支持

“多个硬件信息”支持两层含义：

- 一台设备绑定多个硬件项，例如 CPU + 主板 + 系统盘。
- 同类硬件包含多个可接受值，例如双硬盘或更换前后两块系统盘。

每个绑定槽位包含：

```json
{
  "slot": "system-disk",
  "type": "disk",
  "accepted_hashes": ["sha256:...", "sha256:..."],
  "required": true
}
```

一个槽位的任一 `accepted_hashes` 命中即视为该槽位命中。

### 5.5 批量授权生成

批量签发支持：

- CSV 导入。
- JSON 导入。
- 多个 `.qreq` 文件拖放导入。
- 对全部行应用一个授权模板。
- 每行覆盖模板中的客户、硬件、期限和功能。
- 批量永久授权。
- 批量固定期限授权。
- 批量签发后有效时长和应用实际运行时长授权。
- 混合不同授权模式的批次。
- 预检查、错误汇总和试运行。
- 全部验证通过后再开始签名。
- 为每行生成独立 `license_id`、nonce 和文件。
- 输出签名批次清单和失败报告。

默认批处理语义：

- 输入校验阶段发现错误：不生成任何授权。
- 生成阶段单项密码操作失败：整个批次失败，不发布部分结果。
- 所有文件先写入临时批次目录。
- 全部自验证成功后原子移动到最终目录。
- 已存在同名文件默认拒绝覆盖。

### 5.6 授权读取

签发工具和 Runtime SDK 均支持读取授权，但接口必须区分：

- `inspectEnvelope()`：只读取外层元数据，不代表可信。
- `verifyAndDecrypt()`：验签并解密，返回可信载荷。
- `evaluate()`：进一步校验产品、硬件、时间和功能。

界面不得把“成功解析 JSON”显示成“授权有效”。只有完整验签、解密和策略校验成功才显示有效。

### 5.7 授权模式

#### 永久授权 `perpetual`

- `not_before` 必须为 `null`。
- `expires_at` 必须为 `null`。
- `max_runtime_seconds` 必须为 `null`。
- 不创建时间防回滚状态。
- 系统时间错误不得影响永久授权。
- 仍需校验签名、产品、硬件和功能。

#### 固定日期授权 `fixed_expiry`

- 必须有 `expires_at`。
- 可选 `not_before`。
- 使用 UTC Unix 秒。
- 启用纯软件时间防回滚状态。

#### 签发后有效时长授权 `validity_duration`

- 必须有 `max_runtime_seconds`。
- `expires_at` 必须为 `null`。
- 截止时刻由 `issued_at + max_runtime_seconds` 推导。
- 从签发时刻开始流逝，首次加载前和关机期间仍会消耗。
- 使用纯软件时间防回滚状态抵抗首次运行后的系统时间回拨。

#### 应用实际运行时长授权 `runtime_quota`

- 必须有 `max_runtime_seconds`。
- 不依赖关机期间的系统时间。
- 使用单调时钟累计应用有效运行时间。
- 适合永久离线且无法信任系统日期的场景。

#### 混合授权 `hybrid`

- 同时包含 `expires_at` 和 `max_runtime_seconds`。
- 任一条件达到即过期。
- 默认用于有期限的高强度离线授权。

## 6. 主要工作流

### 6.1 首次初始化

```text
创建密钥库口令
 → 生成 Ed25519 根密钥对
 → 生成 Ed25519 签发密钥对
 → 根私钥签发签发密钥证书
 → 生成产品 XChaCha20 加密密钥
 → 加密保存密钥库
 → 导出 Runtime 公开配置和产品加密配置
 → 制作两份离线加密备份
```

根私钥只用于签发或撤销签发密钥，不用于日常客户授权。

### 6.2 单个永久授权

```text
选择永久授权模板
 → 导入/输入用户硬件
 → 选择绑定项和功能
 → 校验至少一个有效绑定槽位
 → 生成随机 license_id 和 nonce
 → 加密载荷
 → 签名容器
 → 验签、解密、自校验
 → 输出 license.qtlic
```

### 6.3 批量永久授权

```text
导入 devices.csv / devices.json / 多个 qreq
 → 应用 perpetual 模板
 → 规范化每行硬件
 → 检测空值、重复设备和重复订单
 → 展示预检查报告
 → 解锁一次密钥库
 → 为每行独立加密和签名
 → 并行自验证
 → 输出批次目录和 manifest
```

### 6.4 Qt 应用验证

```text
读取指定路径授权文件
 → 校验文件大小和外层字段
 → 验证签发密钥证书
 → 验证授权 Ed25519 签名
 → 解密 XChaCha20-Poly1305 载荷
 → 校验 JSON 模型和 product_id
 → 采集并匹配硬件
 → 按授权模式校验时间
 → 生成不可变 LicenseDecision
 → 开放对应功能
```

## 7. 硬件信息设计

### 7.1 支持类型

| 类型 | Windows 来源 | Linux 来源 | 说明 |
| --- | --- | --- | --- |
| `cpu` | WMI `Win32_Processor.ProcessorId` | ARM `/proc/cpuinfo` Serial；x86 可能不可用 | x86 CPU 通常无可靠唯一序列号 |
| `board` | `Win32_BaseBoard.SerialNumber` | `/sys/devices/virtual/dmi/id/board_serial` | 推荐绑定项 |
| `system_uuid` | `Win32_ComputerSystemProduct.UUID` | `/sys/devices/virtual/dmi/id/product_uuid` | 推荐绑定项 |
| `disk` | `Win32_DiskDrive.SerialNumber` | `/sys/class/block/*/device/serial` | 更换硬盘会失效 |
| `machine_id` | `QSysInfo::machineUniqueId()` | D-Bus machine ID | 克隆系统可能重复 |
| `mac` | 网卡永久地址 | `/sys/class/net/*/address` | 默认不推荐，易变化/伪造 |

采集器不得依赖联网。Windows 采用原生 COM/WMI；Linux 读取 sysfs、procfs 和 Qt API，不调用网络服务。

### 7.2 规范化

所有硬件值在采集端、签发端和验证端使用完全相同的 `fingerprint_version=1` 算法：

1. UTF-8 解码，拒绝无效字节。
2. Unicode NFKC 规范化。
3. 去除 NUL 和首尾空白。
4. 连续空白折叠为一个 ASCII 空格。
5. 转换为大写。
6. UUID 转换为标准 `8-4-4-4-12` 大写格式。
7. 拒绝占位值、全零、全 `F` 和过短值。
8. 计算类型域隔离哈希。

哈希输入：

```text
SHA-256("QTLIC-HW-V1\0" || type_utf8 || "\0" || normalized_value_utf8)
```

拒绝值至少包括：

- `UNKNOWN`
- `NONE`
- `DEFAULT STRING`
- `TO BE FILLED BY O.E.M.`
- `00000000-0000-0000-0000-000000000000`
- 空字符串

授权文件仅保存哈希。原始硬件值只允许在签发操作内存中短暂存在，默认不写审计日志。

### 7.3 匹配策略

```json
{
  "mode": "threshold",
  "minimum": 2,
  "slots": [
    {"slot": "cpu", "type": "cpu", "accepted_hashes": ["sha256:..."]},
    {"slot": "board", "type": "board", "accepted_hashes": ["sha256:..."]},
    {"slot": "disk", "type": "disk", "accepted_hashes": ["sha256:..."]}
  ]
}
```

- `all`：全部槽位命中，默认、最严格。
- `any`：任一槽位命中，复制风险最高，界面显示警告。
- `threshold`：至少 `minimum` 个槽位命中。
- `minimum` 必须在 `1..slots.size()` 范围内。
- 生成端规范化策略：`all` 的 `minimum` 强制等于槽位数，`any` 强制等于 1；只有 `threshold` 接受用户输入的 `minimum`。
- 槽位数量不得为零。

推荐默认值：主板 + system UUID + 系统盘，采用 `threshold=2`。需要最强绑定时采用 `all`。

## 8. 硬件请求文件 `.qreq`

采集器输出硬件请求，不包含任何私钥：

```json
{
  "format": "qt-license-request",
  "version": 1,
  "request_id": "0195...",
  "created_at": 1789948800,
  "product_id": "DataProcessor",
  "fingerprint_version": 1,
  "host": {
    "os": "windows",
    "arch": "x86_64"
  },
  "hardware": [
    {
      "slot": "board",
      "type": "board",
      "hash": "sha256:...",
      "display_hint": "***8F2A"
    },
    {
      "slot": "system-disk",
      "type": "disk",
      "hash": "sha256:...",
      "display_hint": "***31C9"
    }
  ]
}
```

`.qreq` 可以被客户修改，因此签发端只能把它视为输入数据。伪造硬件哈希不会产生通用授权，因为 Runtime 会用实际硬件重新计算并匹配。

## 9. 授权载荷

解密后的载荷模型：

```json
{
  "schema": "qt-license-payload",
  "version": 1,
  "license_id": "0195...",
  "product_id": "DataProcessor",
  "customer": {
    "id": "CUST-00042",
    "name": "Example Customer"
  },
  "order_id": "ORDER-2026-0091",
  "issued_at": 1789948800,
  "license_mode": "perpetual",
  "not_before": null,
  "expires_at": null,
  "max_runtime_seconds": null,
  "state_epoch": 1,
  "fingerprint_version": 1,
  "binding": {
    "mode": "all",
    "minimum": 2,
    "slots": [
      {
        "slot": "board",
        "type": "board",
        "accepted_hashes": ["sha256:..."]
      },
      {
        "slot": "system-disk",
        "type": "disk",
        "accepted_hashes": ["sha256:..."]
      }
    ]
  },
  "features": ["basic", "export", "advanced-chart"],
  "metadata": {
    "issuer": "Internal Licensing Team",
    "note": ""
  }
}
```

约束：

- `license_id` 全局唯一。
- `product_id` 必须与应用编译时产品 ID 完全相等。
- 永久授权的三个时间限制字段必须符合 5.7 节约束。
- 客户名称和备注有长度上限，禁止控制字符。
- `features` 去重并按字典序保存。
- 未知关键字段导致拒绝；未知扩展字段可按版本策略忽略。
- 解密后载荷上限 64 KiB。

## 10. 授权容器 `.qtlic`

### 10.1 外层格式

```json
{
  "magic": "QTLIC",
  "container_version": 1,
  "suite": "ED25519+XCHACHA20POLY1305",
  "kid": "sign-2026-01",
  "ekid": "enc-dataprocessor-01",
  "issuer_certificate": "<Base64Url>",
  "nonce": "<24-byte Base64Url>",
  "ciphertext": "<Base64Url>",
  "signature": "<64-byte Base64Url>"
}
```

Base64Url 一律不带 `=` 填充。字段长度必须先校验，再分配内存。

### 10.2 签名证书

`issuer_certificate` 由根私钥签名，包含：

- `kid`
- 签发公钥
- 允许签发的 `product_id` 列表
- 证书创建时间
- 可选失效时间
- 用途固定为 `license-signing`

Runtime 内置根公钥。这样可更换日常签发密钥而无需重新编译 Runtime。根私钥仍泄露时必须发布新应用版本。

`issuer_certificate` 解码后仍是一个 JSON 信封：

```json
{
  "body": "<Base64Url 原始证书载荷字节>",
  "signature": "<Base64Url 根私钥 Ed25519 签名>"
}
```

`body` 解码后为紧凑 UTF-8 JSON，至少包含：

```json
{
  "schema": "qt-license-issuer-certificate",
  "version": 1,
  "kid": "sign-2026-01",
  "public_key": "<32-byte Base64Url>",
  "product_ids": ["DataProcessor"],
  "usage": "license-signing",
  "not_before": 1789948800,
  "not_after": null
}
```

根签名输入精确定义为：

```text
"QTLIC-ISSUER-CERT-V1\0" || raw_certificate_body
```

Runtime 先对原始 `body` 字节验根签名，再解析证书载荷。外层 `kid` 必须与证书中的 `kid` 相等；许可证 `product_id` 必须出现在 `product_ids` 中。证书有效期使用许可证内已签名的 `issued_at` 判断，不使用 Runtime 当前系统时间，因此永久授权不会因系统时间错误失效。

### 10.3 确定性签名输入

禁止直接对重新序列化后的 JSON 签名。不同 Qt 版本、字段顺序或空白可能产生不同字节。

签名输入使用长度前缀二进制转录：

```text
"QTLIC-SIG-V1\0"
|| LP(container_version_u16_be)
|| LP(suite_utf8)
|| LP(kid_utf8)
|| LP(ekid_utf8)
|| LP(raw_issuer_certificate)
|| LP(raw_nonce)
|| LP(raw_ciphertext)
```

`LP(x)` 定义为 `uint32_be(length(x)) || x`。所有字符串使用严格 UTF-8。

### 10.4 加密

- 算法：XChaCha20-Poly1305 IETF。
- 密钥：按 `ekid` 选择 32 字节产品加密密钥。
- nonce：每个授权随机生成 24 字节，不得重用。
- 明文：紧凑 UTF-8 JSON 载荷。
- AAD 使用以下精确转录：

```text
"QTLIC-AAD-V1\0"
|| LP(container_version_u16_be)
|| LP(suite_utf8)
|| LP(kid_utf8)
|| LP(ekid_utf8)
|| LP(raw_issuer_certificate)
```

- 输出：密文和 16 字节认证标签，由密码库统一返回。

产品加密密钥存在 Runtime 中，只提供内容保密和误用检测。即使该密钥泄露，攻击者仍不能生成有效 Ed25519 签名。

### 10.5 处理顺序

生成端：

```text
校验载荷 → 生成 nonce → AEAD 加密 → 构造签名转录 → Ed25519 签名
→ 写临时文件 → 重新读取 → 验签 → 解密 → 模型比较 → 原子发布
```

验证端：

```text
限制文件大小 → 严格解析外层 → 验证根签名证书 → 验证授权签名
→ AEAD 解密 → 严格解析载荷 → 执行业务策略
```

不得在验签前向界面或日志输出解密后的任何字段。

## 11. 密钥库格式与保护

密钥库扩展名 `.qtkv`：

```json
{
  "magic": "QTKV",
  "version": 1,
  "kdf": "ARGON2ID13",
  "opslimit": 3,
  "memlimit": 268435456,
  "salt": "<16-byte Base64Url>",
  "aead": "XCHACHA20POLY1305",
  "nonce": "<24-byte Base64Url>",
  "ciphertext": "<Base64Url>"
}
```

内部明文包含根私钥、签发私钥和产品加密密钥。保护要求：

- Argon2id 参数从密码库文件读取，但必须满足程序内最低安全值。
- 首次创建时测量设备能力，在可接受启动时间内选择尽可能高参数。
- 口令只通过隐藏输入框或终端安全输入读取，不允许命令行明文参数。
- 解锁后的私钥内存使用 `sodium_mlock()`；使用后 `sodium_memzero()`。
- 空闲 10 分钟自动锁定，可配置但不可关闭超过当前进程生命周期。
- 私钥不得进入 crash dump；签发工具发布版关闭敏感内存转储。
- 至少保存两份离线、加密、介质分离的备份。
- 丢失私钥不能从公钥或授权文件恢复。

## 12. 批量输入与输出

### 12.1 CSV 格式

```csv
row_id,customer_id,customer_name,product_id,license_mode,expires_at,max_runtime_seconds,binding_mode,minimum,cpu,board,system_uuid,disk,features,output_name
1,C001,客户甲,DataProcessor,perpetual,,,all,2,,BOARD-001,UUID-001,DISK-001,basic|export,C001.qtlic
2,C002,客户乙,DataProcessor,hybrid,2027-12-31T23:59:59Z,31536000,threshold,2,CPU-002,BOARD-002,UUID-002,,basic|export|chart,C002.qtlic
```

规则：

- UTF-8，可接受带 BOM 输入，输出默认不带 BOM。
- 日期必须为带时区 ISO 8601，内部转 UTC Unix 秒。
- 功能以 `|` 分隔。
- CSV 仅支持每种硬件一个值；多个候选值使用 JSON。
- `output_name` 只允许文件名，不允许路径分隔符、`..` 或绝对路径。
- 导出 CSV 时，以 `= + - @` 开头的文本必须转义，防止表格公式注入。

### 12.2 JSON 批量格式

```json
{
  "schema": "qt-license-batch",
  "version": 1,
  "defaults": {
    "product_id": "DataProcessor",
    "license_mode": "perpetual",
    "binding_mode": "all",
    "features": ["basic"]
  },
  "records": [
    {
      "row_id": "1",
      "customer_id": "C001",
      "hardware": [
        {"slot": "board", "type": "board", "values": ["BOARD-001"]},
        {"slot": "disk", "type": "disk", "values": ["DISK-A", "DISK-B"]}
      ],
      "output_name": "C001.qtlic"
    }
  ]
}
```

JSON 输入可使用原始硬件值或预先计算的 `sha256:` 指纹，但同一槽位不得混用。

### 12.3 批次清单

成功批次输出：

```text
batch-20260922-001/
├── licenses/
│   ├── C001.qtlic
│   └── C002.qtlic
├── batch-manifest.json
└── batch-report.csv
```

`batch-manifest.json` 包含：

- 批次 ID。
- 创建时间。
- 使用的模板摘要。
- `kid` 和 `ekid`。
- 每个文件的 `license_id`、相对路径、SHA-256。
- 成功、跳过、失败计数。
- 整个清单的 Ed25519 签名。

每次批量签发必须为每个文件生成独立 nonce。禁止为了性能复用 nonce。

## 13. 纯软件离线时间策略

### 13.1 永久授权

永久授权完全跳过时间状态模块：

```text
signature valid
AND product valid
AND hardware valid
AND features valid
= valid
```

系统时间向前、向后、时区变化均不影响永久授权。

### 13.2 限期授权有效时间

```text
effective_utc = max(
    current_system_utc,
    session_start_effective_utc + monotonic_session_elapsed,
    issued_at + persisted_total_runtime
)
```

混合模式满足以下任一条件即过期：

```text
effective_utc >= expires_at
OR persisted_total_runtime >= max_runtime_seconds
```

签发后有效时长模式满足以下条件即过期：

```text
effective_utc >= issued_at + max_runtime_seconds
```

### 13.3 状态模型

```json
{
  "format": "qt-license-state",
  "version": 1,
  "license_id": "0195...",
  "state_epoch": 1,
  "sequence": 1024,
  "max_effective_utc": 1821484700,
  "total_runtime_ms": 78392000,
  "boot_id_hash": "sha256:...",
  "previous_state_hash": "sha256:...",
  "mac": "..."
}
```

状态保存：

- Windows：`ProgramData`、用户应用数据目录、DPAPI 凭据副本。
- Linux：`/var/lib/<product>` 或用户数据目录、用户配置目录、Secret Service/KWallet 副本。
- 无系统级写权限时全部落在用户域，并标记安全级别降低。
- 每 60 秒、主窗口退出、功能操作完成后更新。
- 使用 `QSaveFile` 原子替换。
- 启动时读取所有副本，取合法状态中的最大序号和最大时间。
- 第一次使用某个限期授权且所有副本均不存在时，允许初始化状态；初始化基线不得早于已签名的 `issued_at`。
- 只缺失一个或两个副本、但至少有一个合法副本时，记录安全事件并从最新合法副本修复。
- 合法副本序号差不超过 1 时视为异常退出导致的正常滞后，并自动修复。
- 合法副本序号差大于 1、MAC 错误或内容与 `license_id/state_epoch` 不符时返回 `StateRollbackDetected` 或 `StateCorrupt`。
- 全部状态副本和系统凭据同时被删除时，程序无法区分首次使用和完整回滚；这是纯软件永久离线方案的已知残余风险。

状态 MAC 密钥随机生成：

- Windows 用 DPAPI 机器级保护。
- Linux 优先用 Secret Service/KWallet；否则用权限 `0600` 文件保护。
- 不从公开硬件指纹直接派生 MAC 密钥。

### 13.4 时间异常策略

- 系统时间比历史最大时间早不超过 5 分钟：允许，继续使用历史最大时间。
- 回拨超过 5 分钟：`ClockRollbackDetected`。
- 系统时间向未来推进时接受并持久化最大时间；达到 `expires_at` 立即返回 `Expired`。这会使误调到未来的设备锁定，但避免“调到未来再调回”绕过期限。
- 时间值溢出、早于支持的最小纪元或超出实现上限时返回 `ClockAnomaly`。
- 签发员可生成更高 `state_epoch` 的恢复授权，重建状态。
- 删除状态不能作为恢复方式。

### 13.5 残余风险

完全回滚操作系统镜像可同时回滚授权状态和系统时间。纯软件、永久离线条件下无法可靠检测。需要绝对 UTC 时只能增加联网签名时间或独立安全时钟，这两项均不属于本设计。

## 14. Runtime SDK 设计

### 14.1 对外接口

```cpp
namespace qtlic {

struct VerifyOptions {
    QString productId;
    QString licensePath;
    QByteArray rootPublicKey;
    QHash<QString, QByteArray> productDecryptionKeys;
    bool requireHardwareBinding = true;
};

enum class LicenseStatus {
    Valid,
    FileMissing,
    FileTooLarge,
    MalformedContainer,
    UnsupportedVersion,
    UnknownSigningKey,
    IssuerCertificateInvalid,
    SignatureInvalid,
    UnknownEncryptionKey,
    DecryptionFailed,
    MalformedPayload,
    ProductMismatch,
    HardwareUnavailable,
    HardwareMismatch,
    NotYetValid,
    Expired,
    RuntimeQuotaExceeded,
    ClockRollbackDetected,
    ClockAnomaly,
    StateRollbackDetected,
    StateCorrupt,
    InternalError
};

struct LicenseDecision {
    LicenseStatus status;
    QString licenseId;
    QSet<QString> features;
    qint64 expiresAtUtc = 0;
    bool perpetual = false;

    bool valid() const { return status == LicenseStatus::Valid; }
    bool hasFeature(const QString &feature) const;
};

class LicenseManager {
public:
    static LicenseDecision verify(const VerifyOptions &options);
};

} // namespace qtlic
```

### 14.2 Qt 应用接入

```cpp
qtlic::VerifyOptions options;
options.productId = QStringLiteral("DataProcessor");
options.licensePath = QCoreApplication::applicationDirPath()
                    + QStringLiteral("/license.qtlic");
options.rootPublicKey = QByteArray::fromBase64(kEmbeddedRootPublicKey);
options.productDecryptionKeys.insert(
    QStringLiteral("enc-dataprocessor-01"),
    loadEmbeddedProductKey());

const qtlic::LicenseDecision decision = qtlic::LicenseManager::verify(options);
if (!decision.valid()) {
    showLicenseError(decision.status);
    return EXIT_FAILURE;
}

MainWindow window;
window.setLicensedFeatures(decision.features);
window.show();
```

不能只在 `main()` 校验一次。关键导出、计算、设备控制等入口必须调用统一 `LicenseGate`：

```cpp
if (!licenseGate->allows(QStringLiteral("export"))) {
    return;
}
```

限期授权运行期间每分钟更新状态并重新判断；永久授权无需周期时间检查，但关键功能仍需检查不可变授权决策。

### 14.3 线程与性能

- 首次验证可在工作线程执行，完成前关键功能保持禁用。
- 文件读取上限 256 KiB，解密载荷上限 64 KiB。
- 硬件采集设置单项超时，单项失败不得无限阻塞。
- 验证结果按授权文件哈希缓存，但硬件和限期状态变化必须使缓存失效。
- `LicenseDecision` 创建后不可修改。

## 15. 签发工具界面

### 15.1 密钥库页

- 创建、打开、锁定密钥库。
- 生成根密钥、签发密钥、产品加密密钥。
- 展示公钥指纹和密钥状态。
- 导出 Runtime 配置。
- 加密备份和恢复。
- 密钥轮换向导。

危险操作必须二次确认，但不得显示或复制明文私钥。

### 15.2 单个签发页

- 产品、客户、订单信息。
- 授权模式。
- UTC 起止时间、签发后有效时长或应用实际运行时长。
- 功能复选框。
- 硬件槽位表格：类型、值/哈希、状态、是否选中。
- 匹配策略和阈值。
- 载荷预览。
- 生成并自验证。

永久授权被选中时，日期控件必须禁用并清空，避免残留时间进入载荷。

### 15.3 批量签发页

- 文件导入、模板选择、字段映射。
- 预检查结果表。
- 重复硬件、重复客户、重复订单警告。
- 错误行筛选和导出。
- 试运行。
- 生成进度、取消和最终报告。

取消操作只能发生在当前授权完成后。未发布临时目录安全删除；已发布批次不自动删除。

### 15.4 授权读取页

- 拖放 `.qtlic`。
- 显示容器版本、suite、`kid`、`ekid`。
- 显示根证书和授权签名状态。
- 解密后显示客户、产品、授权模式、硬件策略和功能。
- 可选择“仅检查文件”或“在本机完整评估”。
- 明确区分 `文件有效`、`本机适用` 和 `当前可用`。

### 15.5 审计页

记录：

- 操作时间、操作员、本机标识。
- 批次 ID、客户 ID、产品、授权模式。
- `license_id`、`kid`、输出文件 SHA-256。
- 成功或错误码。

不记录：

- 私钥、密钥库口令、产品解密密钥。
- 原始硬件序列号。
- 解密后的完整授权载荷。

## 16. CLI 设计

```text
qt-license-tool keyvault init
qt-license-tool keyvault export-runtime
qt-license-tool inspect --license file.qtlic
qt-license-tool issue --request device.qreq --template perpetual.json --out file.qtlic
qt-license-tool batch --input devices.csv --template perpetual.json --out batch-dir
qt-license-tool verify --license file.qtlic --hardware device.qreq
```

要求：

- 口令通过终端隐藏输入或标准输入安全通道读取。
- 禁止 `--password plaintext`。
- 支持 `--dry-run`。
- 退出码稳定，可用于离线自动化。
- 标准输出不包含密钥或原始硬件值。

## 17. 核心类

| 类 | 责任 |
| --- | --- |
| `SodiumCryptoProvider` | Ed25519、XChaCha20-Poly1305、Argon2id、随机数、内存清零 |
| `KeyVault` | 密钥库加解锁、密钥查询、备份、轮换 |
| `IssuerCertificateCodec` | 根签名证书编码和验证 |
| `HardwareCollector` | Windows/Linux 原始硬件采集 |
| `HardwareNormalizer` | 规范化、占位值拒绝、SHA-256 |
| `HardwareMatcher` | all/any/threshold 匹配 |
| `LicensePayloadValidator` | 载荷结构和跨字段约束 |
| `LicenseContainerCodec` | 容器解析、转录、加密、签名 |
| `LicenseIssuer` | 单个授权生成和自验证 |
| `BatchIssuer` | 批量预检、生成、manifest 和原子发布 |
| `LicenseVerifier` | 验签、解密、产品和硬件判断 |
| `OfflineTimeGuard` | 有效时间计算、回拨检测、运行时累计 |
| `LicenseStateStore` | 多副本状态、MAC、哈希链、原子写 |
| `LicenseGate` | 业务功能授权入口 |

所有 GUI 和 CLI 必须复用这些核心类，不允许复制协议或密码逻辑。

## 18. 威胁模型

| ID | 威胁 | 控制 | 残余风险 |
| --- | --- | --- | --- |
| T-01 | 修改授权期限或功能 | Ed25519 签名、严格模型校验 | 二进制补丁绕过验证 |
| T-02 | 伪造授权 | 私钥仅在签发端、根/签发分层 | 签发端私钥泄露 |
| T-03 | 复制到其他机器 | 多硬件哈希绑定 | 硬件 ID 克隆或模拟 |
| T-04 | 系统时间回拨 | 历史最大时间、单调时钟、应用实际运行时长 | 全系统快照回滚 |
| T-05 | 本地状态回滚 | 多副本、MAC、序号、哈希链 | 同时回滚全部副本 |
| T-06 | 解密密钥提取 | 签名独立于加密、密钥拆分/混淆仅提高成本 | 本地密钥最终可提取 |
| T-07 | 签发私钥窃取 | Argon2id 密钥库、最小权限、内存清零、离线备份 | 签发机被完全控制 |
| T-08 | 恶意/畸形授权文件 | 大小限制、长度先验、严格 Base64、严格 JSON | 密码库或解析器漏洞 |
| T-09 | 批量输入路径穿越 | 文件名白名单、固定输出根、原子目录 | 签发员主动绕过程序 |
| T-10 | 批量 nonce 重用 | CSPRNG、每授权独立 nonce、测试钩子禁入发布版 | 操作系统随机源失效 |
| T-11 | 调试器跳过检查 | 关键入口重复授权、完整性检查、发布版符号处理 | 本地代码总可被修改 |
| T-12 | 吊销永久离线授权 | 签名离线吊销包、应用更新 | 用户拒绝安装吊销包 |

## 19. 安全要求与验收标准

### SR-001 授权不可伪造

- 优先级：Critical
- 威胁：T-01、T-02
- 要求：所有授权必须由受信任签发密钥进行 Ed25519 签名。
- 验收：任意修改容器或载荷后，验证结果必须为 `SignatureInvalid` 或 `DecryptionFailed`。

### SR-002 私钥隔离

- 优先级：Critical
- 威胁：T-02、T-07
- 要求：Runtime、Collector、授权文件和 Runtime 配置包不得包含签名私钥。
- 验收：对全部交付包执行秘密扫描，不得发现私钥材料。

### SR-003 至少一个硬件绑定

- 优先级：Critical
- 威胁：T-03
- 要求：没有有效绑定槽位时禁止签发。
- 验收：空硬件、占位硬件和零槽位批次均预检失败。

### SR-004 永久授权时间独立

- 优先级：High
- 要求：永久授权不依赖系统时间或状态文件。
- 验收：系统时间设置到过去或未来、删除时间状态，永久授权仍按硬件和功能正常工作。

### SR-005 限期授权防常规回拨

- 优先级：High
- 威胁：T-04、T-05
- 要求：系统时间不能低于已接受最大时间并继续授权。
- 验收：回拨超过容差后返回 `ClockRollbackDetected`。

### SR-006 跨平台协议一致

- 优先级：Critical
- 要求：Windows 生成的授权必须能在 Linux 验证，反向同样成立。
- 验收：共享黄金测试向量逐字节一致，所有平台验证结果一致。

### SR-007 批次原子发布

- 优先级：High
- 要求：批次不得发布未自验证或部分完成的授权集合。
- 验收：模拟第 N 个文件失败，最终输出目录不得出现部分批次。

### SR-008 密码库保护

- 优先级：Critical
- 威胁：T-07
- 要求：私钥静态存储必须使用 Argon2id 派生密钥和 AEAD 加密。
- 验收：错误口令、篡改密钥库或降低 KDF 参数均无法解锁。

## 20. 测试设计

### 20.1 密码协议测试

- 固定密钥、nonce、载荷的黄金测试向量。
- Windows 生成、Linux 验证。
- Linux 生成、Windows 验证。
- 修改签名每一个字节。
- 修改密文、nonce、`kid`、`ekid` 和证书。
- 错误根公钥、错误签发公钥、错误产品解密密钥。
- 超长、截断、重复字段和非法 Base64Url。
- 100,000 次随机 nonce 不重复统计测试。

### 20.2 授权模式测试

- 单个永久授权。
- 批量永久授权。
- 固定日期边界：`now == expires_at` 必须过期。
- 签发后有效时长和应用实际运行时长边界。
- 混合模式两个条件分别先达到。
- 永久授权时间字段非空必须拒绝。
- 限期授权缺少必须字段必须拒绝。

### 20.3 硬件测试

- 单绑定、多绑定、同类型多候选值。
- `all`、`any`、`threshold`。
- 不可用硬件项。
- WMI/sysfs 返回占位值。
- UUID 大小写和格式差异。
- 硬盘更换、主板更换、虚拟机克隆。
- 相同原始值在 Collector、Issuer、Runtime 得到相同哈希。

### 20.4 时间和状态测试

- 系统时间小幅 NTP 回调。
- 大幅回拨。
- 向未来误调后再恢复。
- 运行期间冻结墙上时钟。
- 删除一个、两个、全部状态副本。
- 恢复旧状态副本。
- 异常退出和写入中断。
- `state_epoch` 恢复授权。

### 20.5 批量测试

- 1、10、1,000、100,000 行。
- 重复客户、重复硬件、重复输出名。
- 部分无效行。
- 输出目录无权限。
- 中途取消。
- 模拟磁盘空间不足。
- 同名文件默认不覆盖。
- manifest 中文件哈希全部正确。

### 20.6 模糊测试

对以下入口执行 fuzz：

- `.qtlic` 外层解析。
- Base64Url 解码。
- 证书解析。
- 解密后载荷解析。
- CSV/JSON 批量导入。
- 硬件规范化。

## 21. 构建与依赖

### 21.1 Qt

- Runtime：`QT += core`
- Issuer：`QT += core gui widgets concurrent`
- Collector：`QT += core gui widgets`
- C++ 标准：当前项目保持 C++14；迁移 Qt 6 后可提升到 C++17。

### 21.2 密码库

使用 libsodium，禁止自研 Ed25519、XChaCha20 或 Argon2id。

依赖要求：

- 固定经过评审的 libsodium 版本和发布包 SHA-256。
- Windows 随应用部署匹配架构的 DLL，或经许可证审核后静态链接。
- Linux 使用受控安装包或随应用部署受控 `.so`。
- 启动时调用 `sodium_init()`，失败则授权模块 fail closed。
- 构建产物记录 libsodium 版本。

### 21.3 qmake 子项目

```qmake
TEMPLATE = subdirs

SUBDIRS += \
    common \
    runtime \
    collector \
    issuer \
    cli \
    tests
```

Runtime 应输出静态库或源码模块，业务应用只链接 Runtime，不链接 Issuer。

## 22. 文件与路径安全

- Runtime 授权路径由应用配置，但必须转为绝对规范路径。
- 文件大小在读取前检查。
- 不跟随不受信任目录中的任意相对路径。
- 签发输出名只允许安全字符和单层文件名。
- 临时文件和最终文件必须位于同一文件系统，保证原子重命名。
- Windows 私钥库使用当前签发用户 ACL。
- Linux 私钥库权限必须为 `0600`，父目录为 `0700`。
- 应用日志不得打印密文、原始硬件值或任何密钥。

## 23. 离线吊销与密钥轮换

永久离线意味着无法强制客户接收吊销信息。可提供：

- 根私钥签名的 `revocations.qrl`。
- 吊销 `license_id`、`kid` 或客户 ID。
- Runtime 配置包更新。
- 新应用版本内置最新吊销表。

局限：客户不安装新吊销包或新应用版本时，已发永久授权无法被远程吊销。

签发密钥轮换：

1. 根私钥签发新签发密钥证书。
2. 新授权使用新 `kid`。
3. Runtime 通过随授权携带的根签名证书验证新公钥。
4. 旧密钥先标记 `retired`，停止签发但保留验证。
5. 确认泄露时标记 `compromised`，通过吊销包或应用更新拒绝。

产品加密密钥轮换需要 Runtime 同时包含新旧 `ekid` 对应密钥。旧授权淘汰后才能移除旧密钥。

## 24. 发布和运维

### 24.1 签发端

- 使用专用离线电脑。
- 默认禁用网络接口不是协议要求，但建议作为运维控制。
- 签发员使用非管理员日常账号。
- 密钥库仅在签发期间解锁。
- 批次输出通过受控移动介质传递。
- 定期验证两份密钥库备份可恢复。

### 24.2 验证端

- 应用、Runtime 和 libsodium 一起代码签名或包签名。
- Release 构建，移除不必要符号和调试接口。
- 授权失败默认关闭受保护功能。
- 错误信息面向用户简洁，详细诊断写入不含秘密的本地日志。
- 永久授权不创建无意义的时间状态文件。

## 25. 实施阶段

### 阶段一：协议与核心库

- 密钥库。
- 授权容器。
- 单个永久/限期授权。
- Runtime 验证。
- 黄金测试向量。

完成标准：Windows、Linux 交叉生成验证全部通过。

### 阶段二：硬件采集与 Qt 接入

- Windows WMI。
- Linux sysfs/procfs。
- 硬件规范化和匹配。
- 示例 Qt 应用。

完成标准：硬件变更矩阵测试通过。

### 阶段三：批量签发

- CSV/JSON/qreq 导入。
- 模板、预检、批次原子发布。
- manifest 和审计。

完成标准：10 万行压力测试、失败回滚测试通过。

### 阶段四：离线时间加固

- 多副本状态。
- DPAPI、Secret Service/KWallet。
- 单调时钟和应用实际运行时长。
- `state_epoch` 恢复授权。

完成标准：时间和状态攻击测试全部符合预期错误码。

### 阶段五：安全加固

- 模糊测试。
- 二进制加固和代码签名。
- 密钥轮换和离线吊销包。
- 第三方安全审计。

## 26. 默认产品决策

若实现阶段没有新决策，采用以下默认值：

- 永久授权是一级功能，使用 `perpetual + null` 时间字段。
- 限期授权默认使用 `hybrid`。
- 硬件默认绑定主板、system UUID、系统盘，`threshold=2`。
- 授权必须至少包含一个硬件槽位。
- 加密套件固定为 Ed25519 + XChaCha20-Poly1305。
- 密钥库固定使用 Argon2id + XChaCha20-Poly1305。
- 批量任务先全量预检，再全量生成，最后原子发布。
- 任何生成文件必须由生成端立即自验证。
- 验证端永不联网。
- 永久授权不受系统时间影响。
- 对纯软件离线限期授权只承诺防常规回拨，不承诺抵抗完整系统快照。

## 27. 参考资料

- [libsodium Public-key signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
- [libsodium Password hashing](https://doc.libsodium.org/password_hashing/default_phf)
- [Qt QSysInfo](https://doc.qt.io/qt-6.11/qsysinfo.html)
- [Qt QElapsedTimer](https://doc.qt.io/qt-6.8/qelapsedtimer.html)
- [Microsoft CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [Microsoft QueryUnbiasedInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime)
