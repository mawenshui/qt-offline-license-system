# Qt 应用接入指南

## 1. 链接 Runtime SDK

在业务应用 `.pro` 中加入：

```qmake
LICENSESYSTEM_ROOT = $$clean_path($$PWD/../LicenseSystem)
SODIUM_ROOT = $$LICENSESYSTEM_ROOT/third_party/libsodium

INCLUDEPATH += $$LICENSESYSTEM_ROOT/core
LIBS += -L$$LICENSESYSTEM_ROOT/bin/lib -lQtLicenseCore
PRE_TARGETDEPS += $$LICENSESYSTEM_ROOT/bin/lib/libQtLicenseCore.a
include($$LICENSESYSTEM_ROOT/third_party/libsodium/libsodium.pri)

win32: LIBS += -lcrypt32
```

用签发工具导出的 `qtlicense_runtime_config.h` 应编译进应用，不要在运行时从可替换的明文配置加载信任根。

## 2. 启动验证

```cpp
#include "license_codec.h"
#include "license_runtime.h"
#include "qtlicense_runtime_config.h"

#include <QCoreApplication>
#include <QDir>
#include <QStandardPaths>
#include <QTimer>

qtlic::LicenseRuntimeSession session;

QByteArray rootKey;
QByteArray productKey;
qtlic::LicenseCodec::base64UrlDecode(
    QString::fromLatin1(QTLIC_ROOT_PUBLIC_KEY_B64URL), &rootKey);
qtlic::LicenseCodec::base64UrlDecode(
    QString::fromLatin1(QTLIC_PRODUCT_KEY_B64URL), &productKey);

qtlic::VerifyOptions options;
options.productId = QString::fromLatin1(QTLIC_PRODUCT_ID);
options.licensePath = QDir(QCoreApplication::applicationDirPath())
    .filePath(QStringLiteral("license.qtlic"));
options.rootPublicKey = rootKey;
options.productDecryptionKeys.insert(
    QString::fromLatin1(QTLIC_ENCRYPTION_KEY_ID), productKey);
options.stateDirectory = QDir(
    QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation))
    .filePath(QStringLiteral("license-state"));

const qtlic::LicenseDecision decision = session.start(options);
if (!decision.valid()) {
    // 显示 decision.message，随后退出；不要进入主业务窗口。
    return 2;
}
```

`start()` 顺序固定：解析上限检查 → 根证书验证 → 密文签名验证 → 解密 → 产品检查 → 硬件匹配 → 离线时间状态检查。任何一步失败均拒绝授权。

## 3. 运行中检查

启动验证不够。固定期限、运行时长或混合授权必须使用单调计时器持续记账：

```cpp
QTimer checkpointTimer;
checkpointTimer.setInterval(30 * 1000);
QObject::connect(&checkpointTimer, &QTimer::timeout, [&]() {
    const qtlic::LicenseDecision current = session.checkpoint();
    if (!current.valid()) {
        checkpointTimer.stop();
        // 立即停止受控功能、保存业务数据、提示原因并退出。
    }
});
checkpointTimer.start();
```

建议间隔 15–60 秒。间隔越短，异常断电或强杀进程可漏记的运行时长越少，磁盘写入越多。应用恢复前台、休眠唤醒、进入关键功能前也应调用一次 `checkpoint()`。

永久授权仍需 `start()` 做验签和硬件校验；其运行期检查不访问时间状态。

## 4. 功能开关

```cpp
if (!session.decision().hasFeature(QStringLiteral("export"))) {
    exportAction->setEnabled(false);
}
```

关键操作服务层必须再次检查，不要只隐藏按钮。可以在多个业务入口调用统一守卫函数，守卫同时检查 `session.isActive()`、`checkpoint()` 结果和功能名。

## 5. 状态和错误处理

必须拒绝以下状态：

- 文件缺失、容器畸形、版本不支持。
- 未知签发密钥、证书或签名无效。
- 解密失败、产品不匹配。
- 硬件不可用或不匹配。
- 尚未生效、已到期、运行额度耗尽。
- 系统时间回拨、状态副本回滚、状态损坏。

不要在状态损坏时自动重建状态，否则删除状态文件即可重置期限。合法换机、重装或状态恢复应由签发端重新授权并提高 `state_epoch` 后处理。

## 6. 加固建议

- Release 构建，去除调试符号，开启编译器/链接器可用的控制流和栈保护。
- 把验证调用分散到启动、关键功能和后台检查点；服务层做最终判断。
- 对业务二进制做平台代码签名，校验安装包完整性。
- 不在日志输出产品解密密钥、密钥库口令、原始硬件序列号或完整授权载荷。
- `qtlicense_runtime_config.h` 中产品解密密钥可被逆向提取；防伪根是签名私钥，不是加密密钥。

## 7. 使用 Release 中的源码包

下载 `qt-offline-license-runtime-sdk-vX.Y.Z.zip` 并完整解压。在业务应用 `.pro` 中加入：

```qmake
include($$PWD/path/to/qt-license-runtime-sdk-vX.Y.Z/QtLicenseRuntime.pri)
```

该 `.pri` 只编译运行端所需源码，不包含密钥库和批量签发实现。Windows x64 发布时复制包内 `third_party/libsodium/libsodium-win64/bin/libsodium-26.dll` 到业务可执行文件目录，并使用业务 Qt 套件的 `windeployqt --release` 部署 Qt 运行库。

源码包不会提供 `qtlicense_runtime_config.h`，因为该文件包含每个产品独有的解密密钥，必须由使用者自己的签发密钥库导出并在私有构建环境使用。

## 8. 版本兼容

- v1.0.1 签发器生成授权容器和载荷 `version: 1`，要求目标 Runtime SDK 系列为 `1.x`，最低支持版本为 `1.0.0`。
- 签发时选择目标 Runtime；不兼容系列会在生成文件前被拒绝。
- 应用升级 Runtime SDK 时，必须重新执行启动验证、检查点、硬件不匹配、时间回拨和旧授权回归。
- Release 中应用包与 Runtime SDK 包使用同一产品版本号。不要混用来源不明或被修改的源码包；先核对 `SHA256SUMS.txt`。

- 所有本地纯软件授权最终都能被拥有管理员/root 和调试能力的攻击者补丁绕过；需更高对抗等级时增加 TPM/安全芯片、USB Key 或周期性在线证明。
