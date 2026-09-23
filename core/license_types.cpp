#include "license_types.h"

#include <QJsonArray>
#include <QJsonValue>
#include <QRegularExpression>
#include <QtGlobal>

#include <cmath>
#include <functional>

#include "crypto_provider.h"

namespace qtlic {

namespace {

bool readInt64(const QJsonObject &object, const QString &key, qint64 *value, bool nullable,
               QString *error)
{
    const QJsonValue jsonValue = object.value(key);
    if (nullable && (jsonValue.isNull() || jsonValue.isUndefined())) {
        *value = -1;
        return true;
    }
    if (!jsonValue.isDouble()) {
        if (error) {
            *error = QStringLiteral("字段 %1 必须是整数").arg(key);
        }
        return false;
    }
    const double number = jsonValue.toDouble();
    const double maxExactInteger = 9007199254740991.0;
    if (!std::isfinite(number) || number < -maxExactInteger || number > maxExactInteger) {
        if (error) *error = QStringLiteral("字段 %1 超出安全整数范围").arg(key);
        return false;
    }
    const qint64 integer = static_cast<qint64>(number);
    if (number != static_cast<double>(integer)) {
        if (error) {
            *error = QStringLiteral("字段 %1 不是精确整数").arg(key);
        }
        return false;
    }
    *value = integer;
    return true;
}

QJsonValue optionalInt64(qint64 value)
{
    return value < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(static_cast<double>(value));
}

int maximumPossibleBindingMatches(const HardwareBinding &binding)
{
    QHash<QString, int> claimIndexes;
    QVector<QVector<int>> candidates(binding.bindingSlots.size());
    for (int slotIndex = 0; slotIndex < binding.bindingSlots.size(); ++slotIndex) {
        const BindingSlot &slot = binding.bindingSlots.at(slotIndex);
        for (const QString &hash : slot.acceptedHashes) {
            const QString key = slot.type + QChar(0x1f) + hash;
            if (!claimIndexes.contains(key)) claimIndexes.insert(key, claimIndexes.size());
            const int claimIndex = claimIndexes.value(key);
            if (!candidates[slotIndex].contains(claimIndex)) {
                candidates[slotIndex].append(claimIndex);
            }
        }
    }

    QVector<int> claimOwners(claimIndexes.size(), -1);
    std::function<bool(int, QVector<bool> *)> assignSlot;
    assignSlot = [&candidates, &claimOwners, &assignSlot](int slotIndex,
                                                          QVector<bool> *visited) {
        for (int claimIndex : candidates.at(slotIndex)) {
            if (visited->at(claimIndex)) continue;
            (*visited)[claimIndex] = true;
            if (claimOwners.at(claimIndex) < 0
                    || assignSlot(claimOwners.at(claimIndex), visited)) {
                claimOwners[claimIndex] = slotIndex;
                return true;
            }
        }
        return false;
    };

    int matched = 0;
    for (int slotIndex = 0; slotIndex < candidates.size(); ++slotIndex) {
        QVector<bool> visited(claimOwners.size(), false);
        if (assignSlot(slotIndex, &visited)) ++matched;
    }
    return matched;
}

} // namespace

bool KeyVaultMaterial::isComplete() const
{
    return !productId.isEmpty()
            && rootPublicKey.size() == CryptoProvider::SignPublicKeyBytes
            && rootSecretKey.size() == CryptoProvider::SignSecretKeyBytes
            && signingPublicKey.size() == CryptoProvider::SignPublicKeyBytes
            && signingSecretKey.size() == CryptoProvider::SignSecretKeyBytes
            && productEncryptionKey.size() == CryptoProvider::AeadKeyBytes
            && !issuerCertificate.isEmpty();
}

void KeyVaultMaterial::clearSecrets()
{
    CryptoProvider::wipeLocked(rootSecretKey);
    CryptoProvider::wipeLocked(signingSecretKey);
    CryptoProvider::wipeLocked(productEncryptionKey);
    secretsMemoryLocked = false;
}

QString licenseModeToString(LicenseMode mode)
{
    switch (mode) {
    case LicenseMode::Perpetual: return QStringLiteral("perpetual");
    case LicenseMode::FixedExpiry: return QStringLiteral("fixed_expiry");
    case LicenseMode::ValidityDuration: return QStringLiteral("validity_duration");
    case LicenseMode::RuntimeQuota: return QStringLiteral("runtime_quota");
    case LicenseMode::Hybrid: return QStringLiteral("hybrid");
    }
    return QString();
}

bool licenseModeFromString(const QString &text, LicenseMode *mode)
{
    if (!mode) {
        return false;
    }
    if (text == QLatin1String("perpetual")) {
        *mode = LicenseMode::Perpetual;
    } else if (text == QLatin1String("fixed_expiry")) {
        *mode = LicenseMode::FixedExpiry;
    } else if (text == QLatin1String("validity_duration")) {
        *mode = LicenseMode::ValidityDuration;
    } else if (text == QLatin1String("runtime_quota")) {
        *mode = LicenseMode::RuntimeQuota;
    } else if (text == QLatin1String("hybrid")) {
        *mode = LicenseMode::Hybrid;
    } else {
        return false;
    }
    return true;
}

QString licenseStatusToString(LicenseStatus status)
{
    switch (status) {
    case LicenseStatus::Valid: return QStringLiteral("Valid");
    case LicenseStatus::FileMissing: return QStringLiteral("FileMissing");
    case LicenseStatus::FileTooLarge: return QStringLiteral("FileTooLarge");
    case LicenseStatus::MalformedContainer: return QStringLiteral("MalformedContainer");
    case LicenseStatus::UnsupportedVersion: return QStringLiteral("UnsupportedVersion");
    case LicenseStatus::UnknownSigningKey: return QStringLiteral("UnknownSigningKey");
    case LicenseStatus::IssuerCertificateInvalid: return QStringLiteral("IssuerCertificateInvalid");
    case LicenseStatus::SignatureInvalid: return QStringLiteral("SignatureInvalid");
    case LicenseStatus::UnknownEncryptionKey: return QStringLiteral("UnknownEncryptionKey");
    case LicenseStatus::DecryptionFailed: return QStringLiteral("DecryptionFailed");
    case LicenseStatus::MalformedPayload: return QStringLiteral("MalformedPayload");
    case LicenseStatus::ProductMismatch: return QStringLiteral("ProductMismatch");
    case LicenseStatus::HardwareUnavailable: return QStringLiteral("HardwareUnavailable");
    case LicenseStatus::HardwareMismatch: return QStringLiteral("HardwareMismatch");
    case LicenseStatus::NotYetValid: return QStringLiteral("NotYetValid");
    case LicenseStatus::Expired: return QStringLiteral("Expired");
    case LicenseStatus::RuntimeQuotaExceeded: return QStringLiteral("RuntimeQuotaExceeded");
    case LicenseStatus::ClockRollbackDetected: return QStringLiteral("ClockRollbackDetected");
    case LicenseStatus::ClockAnomaly: return QStringLiteral("ClockAnomaly");
    case LicenseStatus::StateRollbackDetected: return QStringLiteral("StateRollbackDetected");
    case LicenseStatus::StateCorrupt: return QStringLiteral("StateCorrupt");
    case LicenseStatus::CryptoUnavailable: return QStringLiteral("CryptoUnavailable");
    case LicenseStatus::IoError: return QStringLiteral("IoError");
    case LicenseStatus::InternalError: return QStringLiteral("InternalError");
    }
    return QStringLiteral("InternalError");
}

QJsonObject licensePayloadToJson(const LicensePayload &payload)
{
    QJsonObject customer;
    customer.insert(QStringLiteral("id"), payload.customerId);
    customer.insert(QStringLiteral("name"), payload.customerName);

    QJsonArray slotArray;
    for (const BindingSlot &slot : payload.binding.bindingSlots) {
        QJsonArray hashes;
        for (const QString &hash : slot.acceptedHashes) {
            hashes.append(hash);
        }
        QJsonObject item;
        item.insert(QStringLiteral("slot"), slot.slot);
        item.insert(QStringLiteral("type"), slot.type);
        item.insert(QStringLiteral("accepted_hashes"), hashes);
        slotArray.append(item);
    }

    QJsonObject binding;
    binding.insert(QStringLiteral("mode"), payload.binding.mode);
    binding.insert(QStringLiteral("minimum"), payload.binding.minimum);
    binding.insert(QStringLiteral("slots"), slotArray);

    QJsonArray features;
    for (const QString &feature : payload.features) {
        features.append(feature);
    }

    QJsonObject metadata;
    metadata.insert(QStringLiteral("issuer"), payload.issuer);
    metadata.insert(QStringLiteral("note"), payload.note);

    QJsonObject object;
    object.insert(QStringLiteral("schema"), QStringLiteral("qt-license-payload"));
    object.insert(QStringLiteral("version"), payload.version);
    object.insert(QStringLiteral("license_id"), payload.licenseId);
    object.insert(QStringLiteral("product_id"), payload.productId);
    object.insert(QStringLiteral("customer"), customer);
    object.insert(QStringLiteral("order_id"), payload.orderId);
    object.insert(QStringLiteral("issued_at"), static_cast<double>(payload.issuedAt));
    object.insert(QStringLiteral("license_mode"), licenseModeToString(payload.licenseMode));
    object.insert(QStringLiteral("not_before"), optionalInt64(payload.notBefore));
    object.insert(QStringLiteral("expires_at"), optionalInt64(payload.expiresAt));
    object.insert(QStringLiteral("max_runtime_seconds"), optionalInt64(payload.maxRuntimeSeconds));
    object.insert(QStringLiteral("state_epoch"), payload.stateEpoch);
    object.insert(QStringLiteral("fingerprint_version"), payload.fingerprintVersion);
    object.insert(QStringLiteral("binding"), binding);
    object.insert(QStringLiteral("features"), features);
    object.insert(QStringLiteral("metadata"), metadata);
    return object;
}

bool licensePayloadFromJson(const QJsonObject &object, LicensePayload *payload, QString *error)
{
    if (!payload) {
        if (error) *error = QStringLiteral("payload 为空");
        return false;
    }
    if (object.value(QStringLiteral("schema")).toString() != QLatin1String("qt-license-payload")) {
        if (error) *error = QStringLiteral("payload schema 无效");
        return false;
    }

    LicensePayload result;
    result.version = object.value(QStringLiteral("version")).toInt(-1);
    result.licenseId = object.value(QStringLiteral("license_id")).toString();
    result.productId = object.value(QStringLiteral("product_id")).toString();
    const QJsonObject customer = object.value(QStringLiteral("customer")).toObject();
    result.customerId = customer.value(QStringLiteral("id")).toString();
    result.customerName = customer.value(QStringLiteral("name")).toString();
    result.orderId = object.value(QStringLiteral("order_id")).toString();
    if (!readInt64(object, QStringLiteral("issued_at"), &result.issuedAt, false, error)
            || !readInt64(object, QStringLiteral("not_before"), &result.notBefore, true, error)
            || !readInt64(object, QStringLiteral("expires_at"), &result.expiresAt, true, error)
            || !readInt64(object, QStringLiteral("max_runtime_seconds"),
                          &result.maxRuntimeSeconds, true, error)) {
        return false;
    }
    if (!licenseModeFromString(object.value(QStringLiteral("license_mode")).toString(),
                               &result.licenseMode)) {
        if (error) *error = QStringLiteral("授权模式无效（license_mode）");
        return false;
    }
    result.stateEpoch = object.value(QStringLiteral("state_epoch")).toInt(-1);
    result.fingerprintVersion = object.value(QStringLiteral("fingerprint_version")).toInt(-1);

    const QJsonObject binding = object.value(QStringLiteral("binding")).toObject();
    result.binding.mode = binding.value(QStringLiteral("mode")).toString();
    result.binding.minimum = binding.value(QStringLiteral("minimum")).toInt(-1);
    const QJsonArray slotValues = binding.value(QStringLiteral("slots")).toArray();
    for (const QJsonValue &slotValue : slotValues) {
        if (!slotValue.isObject()) {
            if (error) *error = QStringLiteral("binding slot 不是对象");
            return false;
        }
        const QJsonObject slotObject = slotValue.toObject();
        BindingSlot slot;
        slot.slot = slotObject.value(QStringLiteral("slot")).toString();
        slot.type = slotObject.value(QStringLiteral("type")).toString();
        const QJsonArray hashes = slotObject.value(QStringLiteral("accepted_hashes")).toArray();
        for (const QJsonValue &hash : hashes) {
            if (!hash.isString()) {
                if (error) *error = QStringLiteral("硬件哈希不是字符串");
                return false;
            }
            slot.acceptedHashes.append(hash.toString());
        }
        result.binding.bindingSlots.append(slot);
    }

    const QJsonArray features = object.value(QStringLiteral("features")).toArray();
    for (const QJsonValue &feature : features) {
        if (!feature.isString()) {
            if (error) *error = QStringLiteral("feature 不是字符串");
            return false;
        }
        result.features.append(feature.toString());
    }

    const QJsonObject metadata = object.value(QStringLiteral("metadata")).toObject();
    result.issuer = metadata.value(QStringLiteral("issuer")).toString();
    result.note = metadata.value(QStringLiteral("note")).toString();

    if (!validateLicensePayload(result, error)) {
        return false;
    }
    *payload = result;
    return true;
}

bool validateLicensePayload(const LicensePayload &payload, QString *error)
{
    auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };

    if (payload.version != 1 || payload.fingerprintVersion != 1) {
        return fail(QStringLiteral("不支持的 payload 或指纹版本"));
    }
    if (payload.licenseId.isEmpty() || payload.licenseId.size() > 128
            || payload.productId.isEmpty() || payload.productId.size() > 128) {
        return fail(QStringLiteral("授权编号或产品标识无效"));
    }
    const qint64 maximumUtc = 253402300799LL;
    if (payload.issuedAt <= 0 || payload.issuedAt > maximumUtc || payload.stateEpoch < 1
            || payload.notBefore > maximumUtc || payload.expiresAt > maximumUtc
            || payload.maxRuntimeSeconds > maximumUtc) {
        return fail(QStringLiteral("签发时间或授权状态代次无效"));
    }
    if (payload.binding.bindingSlots.isEmpty()) {
        return fail(QStringLiteral("至少需要一个硬件绑定槽位"));
    }
    if (payload.binding.mode != QLatin1String("all")
            && payload.binding.mode != QLatin1String("any")
            && payload.binding.mode != QLatin1String("threshold")) {
        return fail(QStringLiteral("硬件匹配模式无效"));
    }
    if (payload.binding.minimum < 1
            || payload.binding.minimum > payload.binding.bindingSlots.size()) {
        return fail(QStringLiteral("硬件匹配阈值无效"));
    }
    if (payload.binding.mode == QLatin1String("all")
            && payload.binding.minimum != payload.binding.bindingSlots.size()) {
        return fail(QStringLiteral("all 模式的 minimum 必须等于槽位数"));
    }
    if (payload.binding.mode == QLatin1String("any") && payload.binding.minimum != 1) {
        return fail(QStringLiteral("any 模式的 minimum 必须为 1"));
    }
    QSet<QString> slotNames;
    for (const BindingSlot &slot : payload.binding.bindingSlots) {
        if (slot.slot.isEmpty() || slot.type.isEmpty() || slot.acceptedHashes.isEmpty()) {
            return fail(QStringLiteral("硬件绑定槽位不完整"));
        }
        if (slotNames.contains(slot.slot)) {
            return fail(QStringLiteral("硬件槽位重复: %1").arg(slot.slot));
        }
        slotNames.insert(slot.slot);
        QSet<QString> slotHashes;
        for (const QString &hash : slot.acceptedHashes) {
            if (!QRegularExpression(QStringLiteral("^sha256:[0-9a-f]{64}$"))
                    .match(hash).hasMatch()) {
                return fail(QStringLiteral("硬件哈希格式无效"));
            }
            if (slotHashes.contains(hash)) {
                return fail(QStringLiteral("同一硬件槽位包含重复候选"));
            }
            slotHashes.insert(hash);
        }
    }
    if (maximumPossibleBindingMatches(payload.binding) < payload.binding.minimum) {
        return fail(QStringLiteral("硬件候选重复，无法满足匹配阈值"));
    }

    switch (payload.licenseMode) {
    case LicenseMode::Perpetual:
        if (payload.notBefore >= 0 || payload.expiresAt >= 0 || payload.maxRuntimeSeconds >= 0) {
            return fail(QStringLiteral("永久授权不能包含时间限制"));
        }
        break;
    case LicenseMode::FixedExpiry:
        if (payload.expiresAt <= payload.issuedAt || payload.maxRuntimeSeconds >= 0
                || (payload.notBefore >= 0 && payload.notBefore >= payload.expiresAt)) {
            return fail(QStringLiteral("固定期限授权字段无效"));
        }
        break;
    case LicenseMode::ValidityDuration:
        if (payload.maxRuntimeSeconds <= 0 || payload.expiresAt >= 0
                || payload.maxRuntimeSeconds > maximumUtc - payload.issuedAt
                || (payload.notBefore >= 0
                    && payload.notBefore >= payload.issuedAt + payload.maxRuntimeSeconds)) {
            return fail(QStringLiteral("签发后有效时长授权字段无效"));
        }
        break;
    case LicenseMode::RuntimeQuota:
        if (payload.maxRuntimeSeconds <= 0 || payload.expiresAt >= 0) {
            return fail(QStringLiteral("累计运行时长授权字段无效"));
        }
        break;
    case LicenseMode::Hybrid:
        if (payload.expiresAt <= payload.issuedAt || payload.maxRuntimeSeconds <= 0
                || (payload.notBefore >= 0 && payload.notBefore >= payload.expiresAt)) {
            return fail(QStringLiteral("混合授权字段无效"));
        }
        break;
    }

    QSet<QString> uniqueFeatures;
    for (const QString &feature : payload.features) {
        if (feature.isEmpty() || feature.size() > 128 || uniqueFeatures.contains(feature)) {
            return fail(QStringLiteral("功能项为空、过长或重复"));
        }
        uniqueFeatures.insert(feature);
    }
    if (payload.customerId.size() > 256 || payload.customerName.size() > 256
            || payload.orderId.size() > 256 || payload.issuer.size() > 256
            || payload.note.size() > 2048) {
        return fail(QStringLiteral("文本字段过长"));
    }
    return true;
}

} // namespace qtlic
