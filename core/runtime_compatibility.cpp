#include "runtime_compatibility.h"

namespace qtlic {

RuntimeCompatibilityResult RuntimeCompatibility::check(
        const QString &targetRuntimeSeries, const LicensePayload &payload)
{
    RuntimeCompatibilityResult result;
    result.minimumVersion = QStringLiteral("1.0.0");
    if (payload.version != 1 || payload.fingerprintVersion != 1) {
        result.message = QStringLiteral(
                    "当前授权格式至少需要 Runtime SDK %1。")
                .arg(result.minimumVersion);
        return result;
    }
    if (targetRuntimeSeries != QLatin1String("1.x")) {
        result.message = QStringLiteral(
                    "所选运行端系列不支持授权格式 v1；最低兼容版本为 %1。")
                .arg(result.minimumVersion);
        return result;
    }
    result.compatible = true;
    result.message = QStringLiteral("兼容 Runtime SDK 1.x（最低 %1）。")
            .arg(result.minimumVersion);
    return result;
}

} // namespace qtlic
