# Qt License Runtime SDK

此包包含目标 Qt 应用执行授权验签、解密、硬件匹配和离线时间检查所需的最小源码集合。

## 接入

将整个目录放到业务项目中，在 `.pro` 添加：

```qmake
include($$PWD/path/to/qt-license-runtime-sdk/QtLicenseRuntime.pri)
```

再把签发器导出的 `qtlicense_runtime_config.h` 放入业务源码，并按 `docs/Qt应用接入指南.md` 调用 `LicenseRuntimeSession::start()` 和 `checkpoint()`。

Windows 发布目录还必须包含 `third_party/libsodium/libsodium-win64/bin/libsodium-26.dll`。`qtlicense_runtime_config.h` 和 `runtime-config.json` 含产品解密密钥，不能提交到公开仓库；生产应用应编译头文件版本。

本包不包含签发私钥、密钥库、口令、客户授权或硬件请求。

## 兼容性

Runtime SDK 1.x 支持容器和载荷 `version: 1`、硬件指纹版本 1。v1.0.1 签发器会在签发前检查目标 Runtime 系列；不要用 1.x Runtime 接收未来不兼容的载荷版本。应用包与 SDK 包版本应一致，并按 Release 的 `SHA256SUMS.txt` 校验。

## 编译冒烟测试

```powershell
New-Item -ItemType Directory build-smoke | Out-Null
Set-Location build-smoke
qmake ..\examples\smoke\smoke.pro CONFIG+=release
mingw32-make -j4
```

该示例会编译源码包中的完整运行端依赖闭包，在 `build-smoke/bin` 生成 `runtime-sdk-smoke.exe` 并复制 libsodium 运行库。

项目发布流程会把 SDK ZIP 解压到临时目录，独立执行以上构建并运行生成的程序，避免源码包遗漏依赖。
