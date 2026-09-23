#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QThread>

#include <cstdio>

#include "batch_issuer.h"
#include "audit_logger.h"
#include "crypto_provider.h"
#include "hardware_fingerprint.h"
#include "key_vault.h"
#include "license_codec.h"
#include "license_runtime.h"
#include "offline_time_guard.h"
#include "runtime_compatibility.h"

using namespace qtlic;

namespace {

bool check(bool condition, const QString &message)
{
    if (!condition) {
        const QByteArray utf8 = message.toUtf8();
        std::fprintf(stderr, "FAIL: %s\n", utf8.constData());
        std::fflush(stderr);
    }
    return condition;
}

bool writeBytes(const QString &path, const QByteArray &bytes)
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly | QIODevice::Truncate)
            && file.write(bytes) == bytes.size();
}

LicensePayload permanentPayload(const QString &productId, const HardwareValue &hardware,
                                qint64 issuedAt)
{
    LicensePayload payload;
    payload.licenseId = QStringLiteral("test-license-perpetual");
    payload.productId = productId;
    payload.customerId = QStringLiteral("C001");
    payload.customerName = QStringLiteral("测试客户");
    payload.issuedAt = issuedAt;
    payload.licenseMode = LicenseMode::Perpetual;
    payload.features << QStringLiteral("basic") << QStringLiteral("export");
    payload.binding = HardwareFingerprint::bindingFromValues(
                QVector<HardwareValue>() << hardware, QStringLiteral("all"), 1);
    return payload;
}

bool writeBatch(const QString &path, const QString &productId,
                const QStringList &outputNames = QStringList())
{
    QJsonObject defaults;
    defaults.insert(QStringLiteral("product_id"), productId);
    defaults.insert(QStringLiteral("license_mode"), QStringLiteral("perpetual"));
    defaults.insert(QStringLiteral("binding_mode"), QStringLiteral("all"));
    defaults.insert(QStringLiteral("features"), QJsonArray() << QStringLiteral("basic"));
    QJsonArray records;
    for (int i = 1; i <= 2; ++i) {
        QJsonObject hw;
        hw.insert(QStringLiteral("slot"), QStringLiteral("board"));
        hw.insert(QStringLiteral("type"), QStringLiteral("board"));
        hw.insert(QStringLiteral("values"), QJsonArray() << QStringLiteral("BOARD-%1").arg(i));
        QJsonObject record;
        record.insert(QStringLiteral("row_id"), QString::number(i));
        record.insert(QStringLiteral("customer_id"), QStringLiteral("C%1").arg(i));
        record.insert(QStringLiteral("hardware"), QJsonArray() << hw);
        record.insert(QStringLiteral("output_name"), outputNames.size() >= i
                      ? outputNames.at(i - 1) : QStringLiteral("C%1.qtlic").arg(i));
        records.append(record);
    }
    QJsonObject root;
    root.insert(QStringLiteral("schema"), QStringLiteral("qt-license-batch"));
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("defaults"), defaults);
    root.insert(QStringLiteral("records"), records);
    QFile file(path);
    return file.open(QIODevice::WriteOnly)
            && file.write(QJsonDocument(root).toJson(QJsonDocument::Indented)) > 0;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTemporaryDir temp;
    if (!check(temp.isValid(), QStringLiteral("临时目录不可用"))) return 1;

    const QByteArray password("correct horse battery staple");
    const QString productId = QStringLiteral("TestProduct");
    const QString vaultPath = temp.filePath(QStringLiteral("issuer.qtkv"));
    KeyVaultMaterial keys;
    QString error;
    if (!check(KeyVault::create(vaultPath, password, productId, &keys, &error), error)) return 1;

    KeyVaultMaterial unicodeKeys;
    if (!check(!KeyVault::create(temp.filePath(QStringLiteral("short-unicode.qtkv")),
                                 QStringLiteral("一二三四五六七八九").toUtf8(),
                                 QStringLiteral("UnicodeProduct"), &unicodeKeys, &error),
               QStringLiteral("9 个中文字符的口令未被拒绝"))) return 1;
    if (!check(KeyVault::create(temp.filePath(QStringLiteral("valid-unicode.qtkv")),
                                QStringLiteral("一二三四五六七八九十").toUtf8(),
                                QStringLiteral("UnicodeProduct"), &unicodeKeys, &error),
               QStringLiteral("10 个中文字符的口令创建失败: %1").arg(error))) return 1;
    unicodeKeys.clearSecrets();

    KeyVaultMaterial wrong;
    if (!check(!KeyVault::open(vaultPath, QByteArray("wrong password"), &wrong, &error),
               QStringLiteral("错误口令不应打开密钥库"))) return 1;
    KeyVaultMaterial reopened;
    if (!check(KeyVault::open(vaultPath, password, &reopened, &error), error)) return 1;
    if (!check(reopened.rootPublicKey == keys.rootPublicKey, QStringLiteral("密钥库往返不一致"))) return 1;

    QFile vaultFile(vaultPath);
    if (!check(vaultFile.open(QIODevice::ReadOnly), QStringLiteral("读取密钥库测试文件失败"))) return 1;
    const QJsonObject vaultObject = QJsonDocument::fromJson(vaultFile.readAll()).object();
    QJsonObject weakVault = vaultObject;
    weakVault.insert(QStringLiteral("memlimit"), 1024);
    const QString weakVaultPath = temp.filePath(QStringLiteral("weak.qtkv"));
    QFile weakVaultFile(weakVaultPath);
    if (!check(weakVaultFile.open(QIODevice::WriteOnly), QStringLiteral("写 KDF 降级测试失败"))) return 1;
    weakVaultFile.write(QJsonDocument(weakVault).toJson(QJsonDocument::Compact));
    weakVaultFile.close();
    KeyVaultMaterial weakMaterial;
    if (!check(!KeyVault::open(weakVaultPath, password, &weakMaterial, &error),
               QStringLiteral("低于安全下限的 KDF 参数未被拒绝"))) return 1;

    QJsonObject tamperedVault = vaultObject;
    QString vaultCipherText = tamperedVault.value(QStringLiteral("ciphertext")).toString();
    vaultCipherText[0] = vaultCipherText.at(0) == QLatin1Char('A')
            ? QLatin1Char('B') : QLatin1Char('A');
    tamperedVault.insert(QStringLiteral("ciphertext"), vaultCipherText);
    const QString tamperedVaultPath = temp.filePath(QStringLiteral("tampered.qtkv"));
    if (!check(writeBytes(tamperedVaultPath,
                          QJsonDocument(tamperedVault).toJson(QJsonDocument::Compact)),
               QStringLiteral("写篡改密钥库失败"))) return 1;
    KeyVaultMaterial tamperedMaterial;
    if (!check(!KeyVault::open(tamperedVaultPath, password, &tamperedMaterial, &error),
               QStringLiteral("密钥库密文篡改未被 AEAD 拒绝"))) return 1;

    HardwareValue hardware;
    hardware.slot = QStringLiteral("board");
    hardware.type = QStringLiteral("board");
    hardware.value = QStringLiteral("BOARD-TEST-001");
    hardware.hash = HardwareFingerprint::hash(hardware.type, hardware.value);
    if (!check(HardwareFingerprint::slotDisplayName(QStringLiteral("system-uuid"))
               == QStringLiteral("系统 UUID")
               && HardwareFingerprint::slotDisplayName(QStringLiteral("disk-0"))
               == QStringLiteral("硬盘 1")
               && HardwareFingerprint::typeDisplayName(QStringLiteral("machine_id"))
               == QStringLiteral("系统机器标识"),
               QStringLiteral("硬件配置友好名称映射错误"))) return 1;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const LicensePayload payload = permanentPayload(productId, hardware, now);
    const QString licensePath = temp.filePath(QStringLiteral("perpetual.qtlic"));
    if (!check(LicenseCodec::issueToFile(payload, keys, licensePath, &error), error)) return 1;

    VerifyOptions options;
    options.productId = productId;
    options.licensePath = licensePath;
    options.rootPublicKey = keys.rootPublicKey;
    options.productDecryptionKeys.insert(keys.encryptionKeyId, keys.productEncryptionKey);
    options.hardware.append(hardware);
    options.stateDirectory = temp.filePath(QStringLiteral("state-perpetual"));
    const LicenseDecision valid = LicenseCodec::verifyFile(options);
    if (!check(valid.valid() && valid.hasFeature(QStringLiteral("export")), valid.message)) return 1;
    if (!check(!valid.hasFeature(QStringLiteral("admin")),
               QStringLiteral("未授权功能被错误放行"))) return 1;

    VerifyOptions missingOptions = options;
    missingOptions.licensePath = temp.filePath(QStringLiteral("missing.qtlic"));
    if (!check(LicenseCodec::verifyFile(missingOptions).status == LicenseStatus::FileMissing,
               QStringLiteral("缺失授权文件状态错误"))) return 1;

    const QString emptyPath = temp.filePath(QStringLiteral("empty.qtlic"));
    if (!check(writeBytes(emptyPath, QByteArray()), QStringLiteral("创建空授权文件失败"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   emptyPath, productId, keys.rootPublicKey,
                   options.productDecryptionKeys).status == LicenseStatus::MalformedContainer,
               QStringLiteral("空授权文件未归类为格式错误"))) return 1;

    const QString malformedPath = temp.filePath(QStringLiteral("malformed.qtlic"));
    if (!check(writeBytes(malformedPath, QByteArray("{}")),
               QStringLiteral("创建格式错误授权失败"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   malformedPath, productId, keys.rootPublicKey,
                   options.productDecryptionKeys).status == LicenseStatus::MalformedContainer,
               QStringLiteral("缺少容器版本的授权未归类为格式错误"))) return 1;

    QJsonObject unsupportedObject;
    unsupportedObject.insert(QStringLiteral("magic"), QStringLiteral("QTLIC"));
    unsupportedObject.insert(QStringLiteral("container_version"), 2);
    const QString unsupportedPath = temp.filePath(QStringLiteral("unsupported.qtlic"));
    if (!check(writeBytes(unsupportedPath,
                          QJsonDocument(unsupportedObject).toJson(QJsonDocument::Compact)),
               QStringLiteral("创建不支持版本授权失败"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   unsupportedPath, productId, keys.rootPublicKey,
                   options.productDecryptionKeys).status == LicenseStatus::UnsupportedVersion,
               QStringLiteral("未知容器版本状态错误"))) return 1;

    const QString oversizedPath = temp.filePath(QStringLiteral("oversized.qtlic"));
    if (!check(writeBytes(oversizedPath, QByteArray(256 * 1024 + 1, 'x')),
               QStringLiteral("创建超大授权文件失败"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   oversizedPath, productId, keys.rootPublicKey,
                   options.productDecryptionKeys).status == LicenseStatus::FileTooLarge,
               QStringLiteral("超大授权文件状态错误"))) return 1;

    const QByteArray wrongRoot = CryptoProvider::randomBytes(
                CryptoProvider::SignPublicKeyBytes, &error);
    if (!check(LicenseCodec::verifyContainer(
                   licensePath, productId, wrongRoot,
                   options.productDecryptionKeys).status
               == LicenseStatus::IssuerCertificateInvalid,
               QStringLiteral("错误根公钥未拒绝"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   licensePath, productId, keys.rootPublicKey,
                   QHash<QString, QByteArray>()).status
               == LicenseStatus::UnknownEncryptionKey,
               QStringLiteral("缺少产品解密密钥状态错误"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   licensePath, QStringLiteral("OtherProduct"), keys.rootPublicKey,
                   options.productDecryptionKeys).status == LicenseStatus::ProductMismatch,
               QStringLiteral("错误产品未归类为产品不匹配"))) return 1;

    const QString existingOutput = temp.filePath(QStringLiteral("existing.qtlic"));
    const QByteArray sentinel("do-not-overwrite");
    if (!check(writeBytes(existingOutput, sentinel), QStringLiteral("创建已有输出文件失败"))) return 1;
    error.clear();
    if (!check(!LicenseCodec::issueToFile(payload, keys, existingOutput, &error),
               QStringLiteral("签发覆盖了已有授权文件"))) return 1;
    QFile existingFile(existingOutput);
    if (!check(existingFile.open(QIODevice::ReadOnly)
               && existingFile.readAll() == sentinel,
               QStringLiteral("拒绝覆盖后已有文件内容发生变化"))) return 1;

    VerifyOptions mismatchOptions = options;
    mismatchOptions.hardware[0].value = QStringLiteral("BOARD-OTHER");
    mismatchOptions.hardware[0].hash.clear();
    const LicenseDecision mismatch = LicenseCodec::verifyFile(mismatchOptions);
    if (!check(mismatch.status == LicenseStatus::HardwareMismatch,
               QStringLiteral("错误硬件未被拒绝"))) return 1;
    if (!check(mismatch.payload.licenseId == payload.licenseId,
               QStringLiteral("硬件不匹配时丢失已验签授权内容"))) return 1;

    HardwareValue cpuHardware;
    cpuHardware.slot = QStringLiteral("cpu");
    cpuHardware.type = QStringLiteral("cpu");
    cpuHardware.value = QStringLiteral("CPU-TEST-001");
    cpuHardware.hash = HardwareFingerprint::hash(cpuHardware.type, cpuHardware.value);
    const QVector<HardwareValue> twoHardware = QVector<HardwareValue>() << hardware << cpuHardware;
    const HardwareBinding allBinding = HardwareFingerprint::bindingFromValues(
                twoHardware, QStringLiteral("all"), 2, &error);
    const HardwareBinding anyBinding = HardwareFingerprint::bindingFromValues(
                twoHardware, QStringLiteral("any"), 1, &error);
    if (!check(!HardwareFingerprint::matches(allBinding, QVector<HardwareValue>() << hardware)
               && HardwareFingerprint::matches(anyBinding, QVector<HardwareValue>() << hardware),
               QStringLiteral("all/any 硬件匹配策略错误"))) return 1;

    HardwareValue replacement = hardware;
    replacement.value = QStringLiteral("BOARD-TEST-REPLACEMENT");
    replacement.hash = HardwareFingerprint::hash(replacement.type, replacement.value);
    const HardwareBinding alternatives = HardwareFingerprint::bindingFromValues(
                QVector<HardwareValue>() << hardware << replacement,
                QStringLiteral("all"), 1, &error);
    if (!check(HardwareFingerprint::matches(
                   alternatives, QVector<HardwareValue>() << replacement),
               QStringLiteral("同槽位多候选硬件匹配失败"))) return 1;

    HardwareBinding duplicateClaims;
    duplicateClaims.mode = QStringLiteral("all");
    duplicateClaims.minimum = 2;
    BindingSlot duplicateSlotA;
    duplicateSlotA.slot = QStringLiteral("board-a");
    duplicateSlotA.type = hardware.type;
    duplicateSlotA.acceptedHashes << hardware.hash;
    BindingSlot duplicateSlotB = duplicateSlotA;
    duplicateSlotB.slot = QStringLiteral("board-b");
    duplicateClaims.bindingSlots << duplicateSlotA << duplicateSlotB;
    if (!check(!HardwareFingerprint::matches(
                   duplicateClaims, QVector<HardwareValue>() << hardware),
               QStringLiteral("同一物理硬件被重复计为两个绑定槽位"))) return 1;
    LicensePayload duplicateClaimPayload = payload;
    duplicateClaimPayload.licenseId = QStringLiteral("duplicate-hardware-claims");
    duplicateClaimPayload.binding = duplicateClaims;
    if (!check(!validateLicensePayload(duplicateClaimPayload, &error),
               QStringLiteral("签发预检未拒绝跨槽位重复硬件声明"))) return 1;

    HardwareBinding overlappingClaims;
    overlappingClaims.mode = QStringLiteral("all");
    overlappingClaims.minimum = 2;
    BindingSlot flexibleSlot;
    flexibleSlot.slot = QStringLiteral("board-flexible");
    flexibleSlot.type = hardware.type;
    flexibleSlot.acceptedHashes << hardware.hash << replacement.hash;
    BindingSlot strictSlot;
    strictSlot.slot = QStringLiteral("board-strict");
    strictSlot.type = hardware.type;
    strictSlot.acceptedHashes << hardware.hash;
    overlappingClaims.bindingSlots << flexibleSlot << strictSlot;
    if (!check(HardwareFingerprint::matches(
                   overlappingClaims, QVector<HardwareValue>() << hardware << replacement),
               QStringLiteral("硬件槽位最大匹配未找到有效分配"))) return 1;

    QSet<QByteArray> nonces;
    for (int i = 0; i < 5000; ++i) {
        const QByteArray nonce = CryptoProvider::randomBytes(CryptoProvider::AeadNonceBytes, &error);
        if (!check(nonce.size() == CryptoProvider::AeadNonceBytes && !nonces.contains(nonce),
                   QStringLiteral("随机 nonce 生成失败或发生重复"))) return 1;
        nonces.insert(nonce);
    }

    QFile licenseFile(licensePath);
    if (!check(licenseFile.open(QIODevice::ReadOnly), QStringLiteral("读取授权失败"))) return 1;
    QJsonDocument tamperedDocument = QJsonDocument::fromJson(licenseFile.readAll());
    licenseFile.close();
    QJsonObject tamperedObject = tamperedDocument.object();
    QString cipherText = tamperedObject.value(QStringLiteral("ciphertext")).toString();
    cipherText[0] = cipherText.at(0) == QLatin1Char('A') ? QLatin1Char('B') : QLatin1Char('A');
    tamperedObject.insert(QStringLiteral("ciphertext"), cipherText);
    const QString tamperedPath = temp.filePath(QStringLiteral("tampered.qtlic"));
    QFile tamperedFile(tamperedPath);
    if (!check(tamperedFile.open(QIODevice::WriteOnly), QStringLiteral("写篡改授权失败"))) return 1;
    tamperedFile.write(QJsonDocument(tamperedObject).toJson(QJsonDocument::Compact));
    tamperedFile.close();
    const LicenseDecision tampered = LicenseCodec::verifyContainer(
                tamperedPath, productId, keys.rootPublicKey, options.productDecryptionKeys);
    if (!check(tampered.status == LicenseStatus::SignatureInvalid,
               QStringLiteral("密文篡改未在解密前被签名拒绝"))) return 1;

    QJsonObject tamperedHeader = tamperedDocument.object();
    tamperedHeader.insert(QStringLiteral("ekid"), QStringLiteral("enc-attacker"));
    const QString tamperedHeaderPath = temp.filePath(QStringLiteral("tampered-header.qtlic"));
    if (!check(writeBytes(tamperedHeaderPath,
                          QJsonDocument(tamperedHeader).toJson(QJsonDocument::Compact)),
               QStringLiteral("写篡改授权头失败"))) return 1;
    if (!check(LicenseCodec::verifyContainer(
                   tamperedHeaderPath, productId, keys.rootPublicKey,
                   options.productDecryptionKeys).status == LicenseStatus::SignatureInvalid,
               QStringLiteral("加密密钥 ID 篡改未被签名拒绝"))) return 1;

    LicensePayload timed = payload;
    timed.licenseId = QStringLiteral("test-license-timed");
    timed.licenseMode = LicenseMode::FixedExpiry;
    timed.notBefore = now - 10;
    timed.expiresAt = now + 3600;
    timed.note = QStringLiteral("测试授权备注");
    const QString timedPath = temp.filePath(QStringLiteral("timed.qtlic"));
    if (!check(LicenseCodec::issueToFile(timed, keys, timedPath, &error), error)) return 1;
    VerifyOptions timedOptions = options;
    timedOptions.licensePath = timedPath;
    timedOptions.stateDirectory = temp.filePath(QStringLiteral("state-timed"));
    timedOptions.nowUtcOverride = now;
    const LicenseDecision timedDecision = LicenseCodec::verifyFile(timedOptions);
    if (!check(timedDecision.valid() && timedDecision.payload.note == timed.note
               && timedDecision.payload.notBefore == timed.notBefore,
               QStringLiteral("限期授权字段往返验证失败"))) return 1;

    LicensePayload future = timed;
    future.licenseId = QStringLiteral("test-license-future");
    future.notBefore = now + 100;
    const QString futurePath = temp.filePath(QStringLiteral("future.qtlic"));
    if (!check(LicenseCodec::issueToFile(future, keys, futurePath, &error), error)) return 1;
    VerifyOptions futureOptions = options;
    futureOptions.licensePath = futurePath;
    futureOptions.stateDirectory = temp.filePath(QStringLiteral("state-future-before"));
    futureOptions.nowUtcOverride = now + 99;
    if (!check(LicenseCodec::verifyFile(futureOptions).status == LicenseStatus::NotYetValid,
               QStringLiteral("授权在生效时间前被放行"))) return 1;
    futureOptions.stateDirectory = temp.filePath(QStringLiteral("state-future-boundary"));
    futureOptions.nowUtcOverride = now + 100;
    if (!check(LicenseCodec::verifyFile(futureOptions).valid(),
               QStringLiteral("授权在生效时间边界未生效"))) return 1;

    VerifyOptions singleCorruptOptions = timedOptions;
    singleCorruptOptions.stateDirectory = temp.filePath(QStringLiteral("state-single-corrupt"));
    singleCorruptOptions.nowUtcOverride = now;
    if (!check(LicenseCodec::verifyFile(singleCorruptOptions).valid(),
               QStringLiteral("创建单副本损坏测试状态失败"))) return 1;
    QDir singleStateDir(singleCorruptOptions.stateDirectory);
    const QStringList singleStateFiles = singleStateDir.entryList(
                QStringList() << QStringLiteral("*-a.json") << QStringLiteral("*-b.json"),
                QDir::Files);
    if (!check(singleStateFiles.size() == 2
               && writeBytes(singleStateDir.filePath(singleStateFiles.first()), QByteArray("{}"))
               && LicenseCodec::verifyFile(singleCorruptOptions).valid(),
               QStringLiteral("单个状态副本损坏后未自动恢复"))) return 1;

    VerifyOptions bothCorruptOptions = timedOptions;
    bothCorruptOptions.stateDirectory = temp.filePath(QStringLiteral("state-both-corrupt"));
    bothCorruptOptions.nowUtcOverride = now;
    if (!check(LicenseCodec::verifyFile(bothCorruptOptions).valid(),
               QStringLiteral("创建双副本损坏测试状态失败"))) return 1;
    QDir bothStateDir(bothCorruptOptions.stateDirectory);
    const QStringList bothStateFiles = bothStateDir.entryList(
                QStringList() << QStringLiteral("*-a.json") << QStringLiteral("*-b.json"),
                QDir::Files);
    bool bothOverwritten = bothStateFiles.size() == 2;
    for (const QString &name : bothStateFiles) {
        bothOverwritten = bothOverwritten
                && writeBytes(bothStateDir.filePath(name), QByteArray("{}"));
    }
    if (!check(bothOverwritten
               && LicenseCodec::verifyFile(bothCorruptOptions).status
                  == LicenseStatus::StateCorrupt,
               QStringLiteral("双状态副本损坏未安全拒绝"))) return 1;

    VerifyOptions missingKeyOptions = timedOptions;
    missingKeyOptions.stateDirectory = temp.filePath(QStringLiteral("state-missing-key"));
    missingKeyOptions.nowUtcOverride = now;
    if (!check(LicenseCodec::verifyFile(missingKeyOptions).valid(),
               QStringLiteral("创建缺失状态密钥测试状态失败"))) return 1;
    if (!check(QFile::remove(QDir(missingKeyOptions.stateDirectory)
                             .filePath(QStringLiteral("install.key")))
               && LicenseCodec::verifyFile(missingKeyOptions).status
                  == LicenseStatus::StateCorrupt,
               QStringLiteral("有状态时删除安装密钥未安全拒绝"))) return 1;

    LicenseRuntimeSession session;
    timedOptions.stateDirectory = temp.filePath(QStringLiteral("state-session"));
    if (!check(session.start(timedOptions).valid(),
               QStringLiteral("运行期会话启动失败"))) return 1;
    if (!check(session.checkpoint(now + 3601).status == LicenseStatus::Expired,
               QStringLiteral("运行中到期未被拒绝"))) return 1;

    timedOptions.stateDirectory = temp.filePath(QStringLiteral("state-timed"));
    timedOptions.nowUtcOverride = now - 600;
    if (!check(LicenseCodec::verifyFile(timedOptions).status
               == LicenseStatus::ClockRollbackDetected,
               QStringLiteral("时间回拨未被检测"))) return 1;

    VerifyOptions expiryBoundary = options;
    expiryBoundary.licensePath = timedPath;
    expiryBoundary.stateDirectory = temp.filePath(QStringLiteral("state-expiry-boundary"));
    expiryBoundary.nowUtcOverride = timed.expiresAt;
    if (!check(LicenseCodec::verifyFile(expiryBoundary).status == LicenseStatus::Expired,
               QStringLiteral("now == expires_at 边界未过期"))) return 1;

    LicensePayload quota = payload;
    quota.licenseId = QStringLiteral("test-license-quota");
    quota.licenseMode = LicenseMode::RuntimeQuota;
    quota.maxRuntimeSeconds = 10;
    const QString quotaPath = temp.filePath(QStringLiteral("quota.qtlic"));
    if (!check(LicenseCodec::issueToFile(quota, keys, quotaPath, &error), error)) return 1;
    VerifyOptions quotaOptions = options;
    quotaOptions.licensePath = quotaPath;
    quotaOptions.stateDirectory = temp.filePath(QStringLiteral("state-quota"));
    quotaOptions.nowUtcOverride = now;
    if (!check(LicenseCodec::verifyFile(quotaOptions).valid(),
               QStringLiteral("运行时授权首次验证失败"))) return 1;
    VerifyOptions unusedQuotaOptions = quotaOptions;
    unusedQuotaOptions.stateDirectory = temp.filePath(QStringLiteral("state-quota-unused"));
    unusedQuotaOptions.nowUtcOverride = now + 86400;
    if (!check(LicenseCodec::verifyFile(unusedQuotaOptions).valid(),
               QStringLiteral("未运行的实际运行时额度不应随自然时间消耗"))) return 1;
    qint64 effectiveUtc = 0;
    if (!check(OfflineTimeGuard::evaluate(
                   quota, keys.productEncryptionKey, quotaOptions.stateDirectory,
                   now, 10, &effectiveUtc, &error) == LicenseStatus::RuntimeQuotaExceeded,
               QStringLiteral("应用实际运行时长边界未过期"))) return 1;

    LicensePayload oneSecondQuota = quota;
    oneSecondQuota.licenseId = QStringLiteral("test-license-one-second-runtime");
    oneSecondQuota.maxRuntimeSeconds = 1;
    const QString oneSecondPath = temp.filePath(QStringLiteral("one-second-runtime.qtlic"));
    if (!check(LicenseCodec::issueToFile(oneSecondQuota, keys, oneSecondPath, &error), error)) return 1;
    VerifyOptions oneSecondOptions = options;
    oneSecondOptions.licensePath = oneSecondPath;
    oneSecondOptions.stateDirectory = temp.filePath(QStringLiteral("state-one-second-session"));
    oneSecondOptions.nowUtcOverride = now;
    LicenseRuntimeSession runtimeSession;
    if (!check(runtimeSession.start(oneSecondOptions).valid(),
               QStringLiteral("真实运行时会话启动失败"))) return 1;
    QThread::msleep(1100);
    if (!check(runtimeSession.checkpoint(now).status
               == LicenseStatus::RuntimeQuotaExceeded,
               QStringLiteral("真实运行时会话未消耗实际运行额度"))) return 1;

    LicensePayload duration = payload;
    duration.licenseId = QStringLiteral("test-license-validity-duration");
    duration.licenseMode = LicenseMode::ValidityDuration;
    duration.maxRuntimeSeconds = 10;
    const QString durationPath = temp.filePath(QStringLiteral("validity-duration.qtlic"));
    if (!check(LicenseCodec::issueToFile(duration, keys, durationPath, &error), error)) return 1;
    VerifyOptions durationOptions = options;
    durationOptions.licensePath = durationPath;
    durationOptions.stateDirectory = temp.filePath(QStringLiteral("state-duration-valid"));
    durationOptions.nowUtcOverride = now + 9;
    if (!check(LicenseCodec::verifyFile(durationOptions).valid(),
               QStringLiteral("签发后有效时长提前过期"))) return 1;
    durationOptions.stateDirectory = temp.filePath(QStringLiteral("state-duration-expired"));
    durationOptions.nowUtcOverride = now + 10;
    if (!check(LicenseCodec::verifyFile(durationOptions).status == LicenseStatus::Expired,
               QStringLiteral("从未加载的签发后有效时长授权未按签发时间过期"))) return 1;
    durationOptions.stateDirectory = temp.filePath(QStringLiteral("state-duration-first-rollback"));
    durationOptions.nowUtcOverride = now - 3600;
    if (!check(LicenseCodec::verifyFile(durationOptions).status
               == LicenseStatus::ClockRollbackDetected,
               QStringLiteral("首次加载前把系统时间拨到签发时间之前未被拒绝"))) return 1;
    LicensePayload invalidDurationWindow = duration;
    invalidDurationWindow.notBefore = now + 10;
    if (!check(!validateLicensePayload(invalidDurationWindow, &error),
               QStringLiteral("生效时间不早于签发后有效时长截止时间未被拒绝"))) return 1;

    LicensePayload invalidPerpetual = payload;
    invalidPerpetual.expiresAt = now + 10;
    if (!check(!validateLicensePayload(invalidPerpetual, &error),
               QStringLiteral("永久授权携带时间字段未被拒绝"))) return 1;

    LicensePayload invalidWindow = timed;
    invalidWindow.notBefore = invalidWindow.expiresAt;
    if (!check(!validateLicensePayload(invalidWindow, &error),
               QStringLiteral("生效时间不早于到期时间未被拒绝"))) return 1;

    const QString batchInput = temp.filePath(QStringLiteral("batch.json"));
    if (!check(writeBatch(batchInput, productId), QStringLiteral("写批量输入失败"))) return 1;
    BatchIssueResult batchResult;
    if (!check(BatchIssuer::issueFile(batchInput, temp.filePath(QStringLiteral("batch-output")),
                                      keys, &batchResult, &error), error)) return 1;
    if (!check(batchResult.issuedCount == 2
               && QFileInfo::exists(temp.filePath(QStringLiteral("batch-output/licenses/C1.qtlic")))
               && QFileInfo::exists(temp.filePath(QStringLiteral("batch-output/licenses/C2.qtlic")))
               && QFileInfo::exists(temp.filePath(QStringLiteral("batch-output/batch-report.csv")))
               && QFileInfo::exists(temp.filePath(QStringLiteral("batch-output/batch-manifest.json"))),
               QStringLiteral("批量永久授权输出不完整"))) return 1;

    const QString caseBatchInput = temp.filePath(QStringLiteral("batch-case.json"));
    if (!check(writeBatch(caseBatchInput, productId,
                          QStringList() << QStringLiteral("Case.qtlic")
                                        << QStringLiteral("case.qtlic")),
               QStringLiteral("写大小写重复批量输入失败"))) return 1;
    BatchIssueResult rejectedBatch;
    const QString caseOutput = temp.filePath(QStringLiteral("batch-case-output"));
    error.clear();
    if (!check(!BatchIssuer::issueFile(caseBatchInput, caseOutput, keys,
                                       &rejectedBatch, &error)
               && error.contains(QStringLiteral("输出名无效或重复"))
               && !QFileInfo::exists(caseOutput),
               QStringLiteral("批量输出名未按跨平台大小写规则原子拒绝"))) return 1;

    const QString reservedBatchInput = temp.filePath(QStringLiteral("batch-reserved.json"));
    if (!check(writeBatch(reservedBatchInput, productId,
                          QStringList() << QStringLiteral("CON.qtlic")
                                        << QStringLiteral("valid.qtlic")),
               QStringLiteral("写保留文件名批量输入失败"))) return 1;
    const QString reservedOutput = temp.filePath(QStringLiteral("batch-reserved-output"));
    error.clear();
    if (!check(!BatchIssuer::issueFile(reservedBatchInput, reservedOutput, keys,
                                       &rejectedBatch, &error)
               && error.contains(QStringLiteral("输出名无效或重复"))
               && !QFileInfo::exists(reservedOutput),
               QStringLiteral("Windows 保留设备名未在批量预检阶段拒绝"))) return 1;

    const RuntimeCompatibilityResult compatible =
            RuntimeCompatibility::check(QStringLiteral("1.x"), payload);
    if (!check(compatible.compatible && compatible.minimumVersion == QLatin1String("1.0.0"),
               QStringLiteral("Runtime 1.x 兼容预检失败"))) return 1;
    const RuntimeCompatibilityResult incompatible =
            RuntimeCompatibility::check(QStringLiteral("0.x"), payload);
    if (!check(!incompatible.compatible
               && incompatible.message.contains(QStringLiteral("最低兼容版本")),
               QStringLiteral("旧 Runtime 未被兼容预检拒绝"))) return 1;

    const QString auditPath = temp.filePath(QStringLiteral("audit.jsonl"));
    AuditEvent audit;
    audit.action = QStringLiteral("issue_license");
    audit.outcome = QStringLiteral("success");
    audit.productId = productId;
    audit.subjectId = payload.licenseId;
    audit.filePath = licensePath;
    audit.message = QStringLiteral("customer=C001");
    if (!check(AuditLogger::append(audit, auditPath, &error), error)) return 1;
    audit.action = QStringLiteral("verify_license");
    if (!check(AuditLogger::append(audit, auditPath, &error), error)) return 1;
    int auditRecords = 0;
    if (!check(AuditLogger::verify(auditPath, &auditRecords, &error)
               && auditRecords == 2, QStringLiteral("审计日志哈希链验证失败: %1").arg(error))) {
        return 1;
    }
    QFile auditFile(auditPath);
    if (!check(auditFile.open(QIODevice::ReadOnly), QStringLiteral("无法读取审计测试日志"))) return 1;
    QByteArray auditBytes = auditFile.readAll();
    auditFile.close();
    if (!check(!auditBytes.contains("password") && !auditBytes.contains("secret_key"),
               QStringLiteral("审计日志包含敏感字段"))) return 1;
    auditBytes.replace("issue_license", "issue_licensf");
    if (!check(writeBytes(auditPath, auditBytes), QStringLiteral("无法篡改审计测试日志"))) return 1;
    error.clear();
    if (!check(!AuditLogger::verify(auditPath, nullptr, &error)
               && error.contains(QStringLiteral("哈希链")),
               QStringLiteral("审计日志篡改未被检测"))) return 1;

    reopened.clearSecrets();
    keys.clearSecrets();
    std::fprintf(stdout, "All license core scenarios passed\n");
    std::fflush(stdout);
    return 0;
}
