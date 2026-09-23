#include "offline_time_guard.h"

#include "crypto_provider.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStandardPaths>

#include <sodium.h>

#include <cmath>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace qtlic {

namespace {

struct State {
    bool valid = false;
    qint64 sequence = 0;
    qint64 maxEffectiveUtc = 0;
    qint64 totalRuntimeSeconds = 0;
};

QString defaultStateDirectory(const QString &productId)
{
    return QDir(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation))
            .filePath(QStringLiteral("qt-license-state/") + productId);
}

QByteArray protectSecret(const QByteArray &plain, QString *error)
{
#ifdef Q_OS_WIN
    DATA_BLOB input;
    input.cbData = static_cast<DWORD>(plain.size());
    input.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(plain.constData()));
    DATA_BLOB output = {0, nullptr};
    if (!CryptProtectData(&input, L"QtLicenseStateKey", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &output)) {
        if (error) *error = QStringLiteral("DPAPI 保护状态密钥失败: %1").arg(GetLastError());
        return QByteArray();
    }
    const QByteArray protectedBytes(reinterpret_cast<const char *>(output.pbData),
                                    static_cast<int>(output.cbData));
    LocalFree(output.pbData);
    return protectedBytes;
#else
    Q_UNUSED(error)
    return plain;
#endif
}

QByteArray unprotectSecret(const QByteArray &protectedBytes, QString *error)
{
#ifdef Q_OS_WIN
    DATA_BLOB input;
    input.cbData = static_cast<DWORD>(protectedBytes.size());
    input.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(protectedBytes.constData()));
    DATA_BLOB output = {0, nullptr};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        if (error) *error = QStringLiteral("DPAPI 解锁状态密钥失败: %1").arg(GetLastError());
        return QByteArray();
    }
    const QByteArray plain(reinterpret_cast<const char *>(output.pbData),
                           static_cast<int>(output.cbData));
    LocalFree(output.pbData);
    return plain;
#else
    Q_UNUSED(error)
    return protectedBytes;
#endif
}

QByteArray loadOrCreateInstallSecret(const QString &directory, bool stateExists, QString *error)
{
    const QString path = QDir(directory).filePath(QStringLiteral("install.key"));
    QFile file(path);
    if (file.exists()) {
        if (!file.open(QIODevice::ReadOnly)) {
            if (error) *error = QStringLiteral("无法读取安装状态密钥");
            return QByteArray();
        }
        const QByteArray secret = unprotectSecret(file.readAll(), error);
        if (secret.size() != 32) {
            if (error && error->isEmpty()) *error = QStringLiteral("安装状态密钥长度无效");
            return QByteArray();
        }
        return secret;
    }
    if (stateExists) {
        if (error) *error = QStringLiteral("状态文件存在但安装密钥缺失");
        return QByteArray();
    }

    QByteArray secret = CryptoProvider::randomBytes(32, error);
    if (secret.size() != 32) return QByteArray();
    const QByteArray protectedBytes = protectSecret(secret, error);
    if (protectedBytes.isEmpty()) {
        CryptoProvider::wipe(secret);
        return QByteArray();
    }
    QSaveFile output(path);
    if (!output.open(QIODevice::WriteOnly) || output.write(protectedBytes) != protectedBytes.size()
            || !output.commit()) {
        CryptoProvider::wipe(secret);
        if (error) *error = QStringLiteral("无法写入安装状态密钥");
        return QByteArray();
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return secret;
}

QByteArray stateTranscript(const QString &licenseId, int stateEpoch, const State &state)
{
    QByteArray transcript("QTLIC-STATE-V1", 14);
    transcript.append('\0');
    transcript.append(licenseId.toUtf8());
    transcript.append('\0');
    transcript.append(QByteArray::number(stateEpoch));
    transcript.append('\0');
    transcript.append(QByteArray::number(state.sequence));
    transcript.append('\0');
    transcript.append(QByteArray::number(state.maxEffectiveUtc));
    transcript.append('\0');
    transcript.append(QByteArray::number(state.totalRuntimeSeconds));
    return transcript;
}

QByteArray stateMac(const QString &licenseId, int stateEpoch, const State &state,
                    const QByteArray &key)
{
    return CryptoProvider::keyedHash(stateTranscript(licenseId, stateEpoch, state), key);
}

State readState(const QString &path, const QString &licenseId, int stateEpoch,
                const QByteArray &key)
{
    State state;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 16 * 1024) return state;
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return state;
    const QJsonObject object = document.object();
    if (object.value(QStringLiteral("format")).toString() != QLatin1String("qt-license-state")
            || object.value(QStringLiteral("version")).toInt(-1) != 1
            || object.value(QStringLiteral("license_id")).toString() != licenseId
            || object.value(QStringLiteral("state_epoch")).toInt(-1) != stateEpoch) {
        return state;
    }
    auto exactInteger = [&object](const QString &name, qint64 minimum, qint64 maximum,
                                  qint64 *value) {
        const QJsonValue item = object.value(name);
        if (!item.isDouble()) return false;
        const double number = item.toDouble();
        if (!std::isfinite(number) || number < static_cast<double>(minimum)
                || number > static_cast<double>(maximum)) return false;
        const qint64 integer = static_cast<qint64>(number);
        if (number != static_cast<double>(integer)) return false;
        *value = integer;
        return true;
    };
    const qint64 maxExactInteger = 9007199254740991LL;
    if (!exactInteger(QStringLiteral("sequence"), 1, maxExactInteger, &state.sequence)
            || !exactInteger(QStringLiteral("max_effective_utc"), 1, 253402300799LL,
                             &state.maxEffectiveUtc)
            || !exactInteger(QStringLiteral("total_runtime_seconds"), 0, maxExactInteger,
                             &state.totalRuntimeSeconds)) return State();
    const QByteArray expected = stateMac(licenseId, stateEpoch, state, key).toHex();
    const QByteArray actual = object.value(QStringLiteral("mac")).toString().toLatin1();
    if (expected.size() != actual.size() || sodium_memcmp(expected.constData(), actual.constData(),
                                                          static_cast<size_t>(actual.size())) != 0) {
        return State();
    }
    state.valid = true;
    return state;
}

bool writeState(const QString &path, const QString &licenseId, int stateEpoch,
                const State &state, const QByteArray &key, QString *error)
{
    QJsonObject object;
    object.insert(QStringLiteral("format"), QStringLiteral("qt-license-state"));
    object.insert(QStringLiteral("version"), 1);
    object.insert(QStringLiteral("license_id"), licenseId);
    object.insert(QStringLiteral("state_epoch"), stateEpoch);
    object.insert(QStringLiteral("sequence"), static_cast<double>(state.sequence));
    object.insert(QStringLiteral("max_effective_utc"), static_cast<double>(state.maxEffectiveUtc));
    object.insert(QStringLiteral("total_runtime_seconds"),
                  static_cast<double>(state.totalRuntimeSeconds));
    object.insert(QStringLiteral("mac"), QString::fromLatin1(
                      stateMac(licenseId, stateEpoch, state, key).toHex()));
    const QByteArray bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
        if (error) *error = QStringLiteral("授权状态写入失败: %1").arg(path);
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

} // namespace

LicenseStatus OfflineTimeGuard::evaluate(const LicensePayload &payload,
                                         const QByteArray &productKey,
                                         const QString &stateDirectory,
                                         qint64 nowUtc,
                                         qint64 runtimeDeltaSeconds,
                                         qint64 *effectiveUtc,
                                         QString *error)
{
    if (payload.licenseMode == LicenseMode::Perpetual) {
        if (effectiveUtc) *effectiveUtc = 0;
        return LicenseStatus::Valid;
    }
    if (nowUtc <= 0 || nowUtc > 253402300799LL || runtimeDeltaSeconds < 0) {
        if (error) *error = QStringLiteral("系统 UTC 或运行时间增量无效");
        return LicenseStatus::ClockAnomaly;
    }
    if (nowUtc + 300 < payload.issuedAt) {
        if (effectiveUtc) *effectiveUtc = payload.issuedAt;
        if (error) *error = QStringLiteral("系统时间早于授权签发时间");
        return LicenseStatus::ClockRollbackDetected;
    }

    const QString directory = stateDirectory.isEmpty()
            ? defaultStateDirectory(payload.productId) : stateDirectory;
    if (!QDir().mkpath(directory)) {
        if (error) *error = QStringLiteral("无法创建授权状态目录: %1").arg(directory);
        return LicenseStatus::IoError;
    }
    const QString prefix = QString::fromLatin1(QCryptographicHash::hash(
                                                   payload.licenseId.toUtf8(),
                                                   QCryptographicHash::Sha256).toHex().left(24));
    const QString pathA = QDir(directory).filePath(prefix + QStringLiteral("-a.json"));
    const QString pathB = QDir(directory).filePath(prefix + QStringLiteral("-b.json"));
    const bool anyStateFile = QFileInfo::exists(pathA) || QFileInfo::exists(pathB);

    QByteArray installSecret = loadOrCreateInstallSecret(directory, anyStateFile, error);
    if (installSecret.size() != 32) return LicenseStatus::StateCorrupt;
    QByteArray macInput("QTLIC-STATE-KEY-V1", 18);
    macInput.append('\0');
    macInput.append(payload.productId.toUtf8());
    macInput.append('\0');
    macInput.append(installSecret);
    QByteArray stateKey = CryptoProvider::keyedHash(macInput, productKey);
    CryptoProvider::wipe(installSecret);
    if (stateKey.size() != 32) return LicenseStatus::InternalError;

    const State stateA = readState(pathA, payload.licenseId, payload.stateEpoch, stateKey);
    const State stateB = readState(pathB, payload.licenseId, payload.stateEpoch, stateKey);
    if (anyStateFile && !stateA.valid && !stateB.valid) {
        CryptoProvider::wipe(stateKey);
        if (error) *error = QStringLiteral("授权状态副本均无效");
        return LicenseStatus::StateCorrupt;
    }
    if (stateA.valid && stateB.valid && qAbs(stateA.sequence - stateB.sequence) > 1) {
        CryptoProvider::wipe(stateKey);
        if (error) *error = QStringLiteral("授权状态序号出现回滚");
        return LicenseStatus::StateRollbackDetected;
    }

    State current;
    if (stateA.valid && (!stateB.valid || stateA.sequence >= stateB.sequence)) current = stateA;
    else if (stateB.valid) current = stateB;
    else {
        current.valid = true;
        current.sequence = 0;
        current.maxEffectiveUtc = qMax(payload.issuedAt, nowUtc);
        current.totalRuntimeSeconds = 0;
    }

    if (current.sequence > 0 && nowUtc + 300 < current.maxEffectiveUtc) {
        CryptoProvider::wipe(stateKey);
        if (effectiveUtc) *effectiveUtc = current.maxEffectiveUtc;
        if (error) *error = QStringLiteral("检测到系统时间回拨");
        return LicenseStatus::ClockRollbackDetected;
    }

    State next = current;
    const qint64 maxExactInteger = 9007199254740991LL;
    if (current.sequence >= maxExactInteger
            || runtimeDeltaSeconds > maxExactInteger - current.totalRuntimeSeconds
            || runtimeDeltaSeconds > 253402300799LL - current.maxEffectiveUtc) {
        CryptoProvider::wipe(stateKey);
        if (error) *error = QStringLiteral("授权时间状态溢出");
        return LicenseStatus::ClockAnomaly;
    }
    next.sequence += 1;
    next.totalRuntimeSeconds += runtimeDeltaSeconds;
    next.maxEffectiveUtc = qMax(current.maxEffectiveUtc + runtimeDeltaSeconds, nowUtc);
    next.maxEffectiveUtc = qMax(next.maxEffectiveUtc,
                                payload.issuedAt + next.totalRuntimeSeconds);
    if (effectiveUtc) *effectiveUtc = next.maxEffectiveUtc;

    bool writeOk = true;
    if (current.sequence == 0) {
        writeOk = writeState(pathA, payload.licenseId, payload.stateEpoch, next, stateKey, error)
                && writeState(pathB, payload.licenseId, payload.stateEpoch, next, stateKey, error);
    } else {
        const QString target = (next.sequence % 2 == 0) ? pathA : pathB;
        writeOk = writeState(target, payload.licenseId, payload.stateEpoch, next, stateKey, error);
    }
    CryptoProvider::wipe(stateKey);
    if (!writeOk) return LicenseStatus::IoError;

    if (payload.notBefore >= 0 && next.maxEffectiveUtc < payload.notBefore) {
        return LicenseStatus::NotYetValid;
    }
    if ((payload.licenseMode == LicenseMode::FixedExpiry
         || payload.licenseMode == LicenseMode::Hybrid)
            && next.maxEffectiveUtc >= payload.expiresAt) {
        return LicenseStatus::Expired;
    }
    if (payload.licenseMode == LicenseMode::ValidityDuration
            && next.maxEffectiveUtc >= payload.issuedAt + payload.maxRuntimeSeconds) {
        return LicenseStatus::Expired;
    }
    if ((payload.licenseMode == LicenseMode::RuntimeQuota
         || payload.licenseMode == LicenseMode::Hybrid)
            && next.totalRuntimeSeconds >= payload.maxRuntimeSeconds) {
        return LicenseStatus::RuntimeQuotaExceeded;
    }
    return LicenseStatus::Valid;
}

} // namespace qtlic
