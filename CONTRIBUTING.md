# 贡献指南

## 开始前

1. 阅读 [开发全流程](docs/开发全流程.md) 和 [安全边界与运维指南](docs/安全边界与运维指南.md)。
2. 从 `main` 创建 `feature/<name>`、`fix/<name>` 或 `docs/<name>` 分支。
3. 不提交密钥库、授权文件、硬件请求、运行端密钥配置和客户数据。

## 本地验证

至少执行：

```powershell
qmake ..\qt-offline-license-system\LicenseSystem.pro CONFIG+=release
mingw32-make -j4
..\qt-offline-license-system\bin\license-core-tests.exe
```

涉及真实硬件、CLI 或协议的改动还需执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File ..\qt-offline-license-system\tests\real_world_cli.ps1
```

## Pull Request

- 一个 PR 解决一个问题，描述行为变化和验证证据。
- 协议、密码学、密钥、时间状态或文件格式变更必须说明兼容和迁移策略。
- UI 配置名优先使用用户可理解的中文；内部字段名放在 Tooltip、技术数据页或文档中。
- 新增非平凡逻辑必须有一个可运行检查。
