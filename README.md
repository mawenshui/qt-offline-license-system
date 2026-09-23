# Qt 离线授权系统

[![build](https://github.com/mawenshui/qt-offline-license-system/actions/workflows/build.yml/badge.svg)](https://github.com/mawenshui/qt-offline-license-system/actions/workflows/build.yml)

纯 Qt/C++ 实现的离线授权签发、硬件采集与运行端验证方案。签发端可永久离线运行，目标应用通过数字签名、加密载荷、硬件绑定和离线时间状态共同判断授权是否有效。

> 当前公开仓库未附加项目级开源许可证。源码公开用于审阅和协作，不代表自动授予复制、修改或再分发权利。第三方组件遵循各自许可证。

## 功能

- Qt Widgets 图形签发工具与硬件采集器。
- 命令行签发、采集、批量生成、验证和只读检查。
- 永久、固定到期、签发后有效时长、实际运行时长和混合授权。
- CPU、主板、系统 UUID、硬盘和系统机器标识等多项硬件绑定。
- Ed25519 签名、XChaCha20-Poly1305 加密、Argon2id 密钥派生。
- Windows DPAPI / Linux 权限约束下的离线时间防回拨状态。
- 可嵌入业务 Qt 应用的运行端验证源码包。
- 首次使用向导、密钥库状态门控、自动锁定倒计时、即时校验和签发确认摘要。
- 加密备份恢复验证、目标 Runtime 兼容预检和防篡改本地审计日志。

当前版本：`1.0.1`。

## 组件

| 目录 | 用途 |
| --- | --- |
| `issuer/` | 图形签发工具 |
| `collector/` | 客户机硬件采集器 |
| `cli/` | 自动化命令行工具 |
| `core/` | 签发与运行端公共核心 |
| `tests/` | 核心断言及真实进程闭环测试 |
| `examples/` | 批量签发样例 |
| `docs/` | 架构、开发、接入和运维文档 |
| `scripts/` | 可复现发布打包脚本 |

## 快速开始

### 下载已构建版本

从 [Releases](https://github.com/mawenshui/qt-offline-license-system/releases) 下载：

- `qt-offline-license-system-*-windows-x64.zip`：签发器、采集器、CLI 及运行依赖。
- `qt-offline-license-runtime-sdk-*.zip`：目标应用验证/解密所需源码、qmake 配置和接入说明。
- `SHA256SUMS.txt`：发布资产完整性校验值。

签发私钥不会包含在仓库或 Release 中。首次运行时由使用者在受控、离线签发机创建密钥库。

### 从源码构建

要求 Qt 5.12.12 或后续 Qt 5/Qt 6、qmake、C++14。Windows 离线依赖已放在 `third_party/libsodium`；Linux 需安装 `libsodium-dev`。

```powershell
git clone https://github.com/mawenshui/qt-offline-license-system.git
cd qt-offline-license-system
New-Item -ItemType Directory ..\build-license-system | Out-Null
Set-Location ..\build-license-system
qmake ..\qt-offline-license-system\LicenseSystem.pro CONFIG+=release
mingw32-make -j4
..\qt-offline-license-system\bin\license-core-tests.exe
```

完整 Windows、Linux 构建方式见[实现与构建指南](docs/实现与构建指南.md)。

### 完整自动化验证

在仓库根目录执行：

```powershell
.\tests\full_flow.ps1 -Version 1.0.1
```

脚本完成 Release 构建、核心与 UI 测试、真实 CLI 闭环、发布打包、SHA-256 和敏感文件检查、发布包启动及 Runtime SDK 独立构建。

## 基本使用流程

1. 在受控离线电脑运行 `QtLicenseIssuer`，按首次使用向导创建密钥库并制作加密离线备份。
2. 导出运行端配置头文件，编译进目标应用。
3. 客户机运行 `QtHardwareCollector`，生成不含原始序列号的硬件请求。
4. 签发端导入请求，选择授权模式、功能和硬件匹配规则，生成授权文件。
5. 目标应用使用与目标版本匹配的 Runtime SDK，在启动、定时检查点和关键功能入口验证授权。

签发器仅在密钥库解锁后开放签发与导出；签发前执行内联校验、版本兼容检查和确认摘要。审计日志默认写入当前用户本地应用数据目录的 `audit/audit-YYYY-MM.jsonl`，可在密钥库页验证哈希链完整性。

运行端代码示例和安全边界见 [Qt 应用接入指南](docs/Qt应用接入指南.md)。

## 文档

- [开发全流程](docs/开发全流程.md)：需求、分支、实现、验证、发布和回滚。
- [实现与构建指南](docs/实现与构建指南.md)：环境、构建、CLI 和产物。
- [Qt 应用接入指南](docs/Qt应用接入指南.md)：运行端验证/解密接入。
- [详细设计](docs/Qt离线授权系统详细设计.md)：协议、威胁模型和数据格式。
- [安全边界与运维指南](docs/安全边界与运维指南.md)：密钥和生产运维要求。
- [批量输入格式](docs/批量输入格式.md)：CSV/JSON 批量签发格式。
- [真实场景测试报告](docs/真实场景测试报告.md)：已验证场景和限制。
- [用户体验优化说明](docs/用户体验优化说明.md)：用户旅程、已完成界面改造和后续优化优先级。

## 安全说明

- 不要提交或上传 `.qtkv`、`.qtlic`、`.qreq`、`runtime-config.json` 或生成的运行端配置头文件。
- 运行端产品解密密钥可被本地逆向提取；授权防伪根是始终离线保存的签名私钥。
- 本地纯软件授权无法抵抗拥有管理员/root 和调试能力的攻击者永久补丁。
- 安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 开发与贡献

构建、测试和提交要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。变更记录见 [CHANGELOG.md](CHANGELOG.md)。

最后核对：2026-09-23。
