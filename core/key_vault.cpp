#include "key_vault.h"

#include "crypto_provider.h"
#include "license_codec.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>

namespace qtlic {

namespace {

const quint64 DefaultOpsLimit = 3;
const quint64 DefaultMemLimit = 64ULL * 1024ULL * 1024ULL;
const quint64 MinimumOpsLimit = 2;
const quint64 MinimumMemLimit = 32ULL * 1024ULL * 1024ULL;

int passwordCharacterCount(const QByteArray &password)
{
    const QString text = QString::fromUtf8(password.constData(), password.size());
    if (text.toUtf8() != password) return -1;
    return text.toUcs4().size();
}

QString keyId(const QString &prefix, const QByteArray &bytes)
{
    return prefix + QLatin1Char('-')
            + QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256)
                                  .toHex().left(16));
}

QByteArray vaultPlainText(const KeyVaultMaterial &material)
{
    QJsonObject object;
    object.insert(QStringLiteral("schema"), QStringLiteral("qt-license-key-vault"));
    object.insert(QStringLiteral("version"), material.version);
    object.insert(QStringLiteral("product_id"), material.productId);
    object.insert(QStringLiteral("kid"), material.keyId);
    object.insert(QStringLiteral("ekid"), material.encryptionKeyId);
    object.insert(QStringLiteral("root_public"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.rootPublicKey)));
    object.insert(QStringLiteral("root_secret"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.rootSecretKey)));
    object.insert(QStringLiteral("signing_public"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.signingPublicKey)));
    object.insert(QStringLiteral("signing_secret"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.signingSecretKey)));
    object.insert(QStringLiteral("product_encryption_key"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.productEncryptionKey)));
    object.insert(QStringLiteral("issuer_certificate"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.issuerCertificate)));
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

void lockMaterialSecrets(KeyVaultMaterial *material)
{
    QString ignored;
    const bool rootLocked = CryptoProvider::lockMemory(material->rootSecretKey, &ignored);
    const bool signingLocked = CryptoProvider::lockMemory(material->signingSecretKey, &ignored);
    const bool productLocked = CryptoProvider::lockMemory(
                material->productEncryptionKey, &ignored);
    material->secretsMemoryLocked = rootLocked && signingLocked && productLocked;
}

bool decodeVaultPlainText(const QByteArray &bytes, KeyVaultMaterial *material, QString *error)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("密钥库内部 JSON 无效");
        return false;
    }
    const QJsonObject object = document.object();
    if (object.value(QStringLiteral("schema")).toString()
            != QLatin1String("qt-license-key-vault")
            || object.value(QStringLiteral("version")).toInt(-1) != 1) {
        if (error) *error = QStringLiteral("密钥库内部版本无效");
        return false;
    }
    KeyVaultMaterial result;
    result.productId = object.value(QStringLiteral("product_id")).toString();
    result.keyId = object.value(QStringLiteral("kid")).toString();
    result.encryptionKeyId = object.value(QStringLiteral("ekid")).toString();
    if (!LicenseCodec::base64UrlDecode(object.value(QStringLiteral("root_public")).toString(),
                                       &result.rootPublicKey)
            || !LicenseCodec::base64UrlDecode(object.value(QStringLiteral("root_secret")).toString(),
                                              &result.rootSecretKey)
            || !LicenseCodec::base64UrlDecode(
                object.value(QStringLiteral("signing_public")).toString(),
                &result.signingPublicKey)
            || !LicenseCodec::base64UrlDecode(
                object.value(QStringLiteral("signing_secret")).toString(),
                &result.signingSecretKey)
            || !LicenseCodec::base64UrlDecode(
                object.value(QStringLiteral("product_encryption_key")).toString(),
                &result.productEncryptionKey)
            || !LicenseCodec::base64UrlDecode(
                object.value(QStringLiteral("issuer_certificate")).toString(),
                &result.issuerCertificate)
            || !result.isComplete()) {
        result.clearSecrets();
        if (error) *error = QStringLiteral("密钥库内部密钥缺失或长度错误");
        return false;
    }
    lockMaterialSecrets(&result);
    *material = result;
    return true;
}

bool writeBytes(const QString &path, const QByteArray &bytes, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
        if (error) *error = QStringLiteral("文件写入失败: %1").arg(path);
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

} // namespace

bool KeyVault::create(const QString &path, const QByteArray &password,
                      const QString &productId, KeyVaultMaterial *material, QString *error)
{
    if (!material) {
        if (error) *error = QStringLiteral("密钥库输出参数无效");
        return false;
    }
    const int passwordCharacters = passwordCharacterCount(password);
    if (passwordCharacters < 10 || passwordCharacters > 1024) {
        if (error) *error = passwordCharacters < 0
                ? QStringLiteral("密钥库口令不是有效 UTF-8 文本")
                : QStringLiteral("密钥库口令必须为 10–1024 个字符");
        return false;
    }
    if (!QRegularExpression(QStringLiteral("^[A-Za-z0-9._-]{1,128}$"))
            .match(productId.trimmed()).hasMatch()) {
        if (error) *error = QStringLiteral(
                    "产品 ID 必须为 1–128 个 ASCII 字符，仅允许字母、数字、点、下划线和连字符");
        return false;
    }
    if (QFileInfo::exists(path)) {
        if (error) *error = QStringLiteral("密钥库文件已存在，拒绝覆盖");
        return false;
    }
    KeyVaultMaterial result;
    result.productId = productId.trimmed();
    if (!CryptoProvider::generateSignKeyPair(&result.rootPublicKey, &result.rootSecretKey, error)
            || !CryptoProvider::generateSignKeyPair(&result.signingPublicKey,
                                                    &result.signingSecretKey, error)) {
        result.clearSecrets();
        return false;
    }
    result.productEncryptionKey = CryptoProvider::randomBytes(CryptoProvider::AeadKeyBytes, error);
    if (result.productEncryptionKey.size() != CryptoProvider::AeadKeyBytes) {
        result.clearSecrets();
        return false;
    }
    result.keyId = keyId(QStringLiteral("sign"), result.signingPublicKey);
    result.encryptionKeyId = keyId(QStringLiteral("enc"), result.productEncryptionKey);
    result.issuerCertificate = LicenseCodec::createIssuerCertificate(
                result.rootSecretKey, result.signingPublicKey, result.keyId, result.productId,
                QDateTime::currentSecsSinceEpoch() - 60, error);
    if (result.issuerCertificate.isEmpty() || !save(path, password, result, error)) {
        result.clearSecrets();
        return false;
    }
    lockMaterialSecrets(&result);
    *material = result;
    return true;
}

bool KeyVault::open(const QString &path, const QByteArray &password,
                    KeyVaultMaterial *material, QString *error)
{
    if (!material || password.isEmpty()) {
        if (error) *error = QStringLiteral("密钥库口令为空");
        return false;
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() <= 0 || file.size() > 1024 * 1024) {
        if (error) *error = QStringLiteral("无法读取密钥库或文件过大");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("密钥库格式无效");
        return false;
    }
    const QJsonObject object = document.object();
    if (object.value(QStringLiteral("magic")).toString() != QLatin1String("QTKV")
            || object.value(QStringLiteral("version")).toInt(-1) != 1
            || object.value(QStringLiteral("kdf")).toString() != QLatin1String("ARGON2ID13")
            || object.value(QStringLiteral("aead")).toString()
            != QLatin1String("XCHACHA20POLY1305")) {
        if (error) *error = QStringLiteral("密钥库头或算法无效");
        return false;
    }
    const quint64 opsLimit = static_cast<quint64>(
                object.value(QStringLiteral("opslimit")).toDouble(0));
    const quint64 memLimit = static_cast<quint64>(
                object.value(QStringLiteral("memlimit")).toDouble(0));
    if (opsLimit < MinimumOpsLimit || memLimit < MinimumMemLimit
            || opsLimit > 20 || memLimit > 1024ULL * 1024ULL * 1024ULL) {
        if (error) *error = QStringLiteral("密钥库 KDF 参数低于安全下限或异常过大");
        return false;
    }
    QByteArray salt;
    QByteArray nonce;
    QByteArray cipherText;
    if (!LicenseCodec::base64UrlDecode(object.value(QStringLiteral("salt")).toString(), &salt)
            || !LicenseCodec::base64UrlDecode(object.value(QStringLiteral("nonce")).toString(), &nonce)
            || !LicenseCodec::base64UrlDecode(
                object.value(QStringLiteral("ciphertext")).toString(), &cipherText)
            || salt.size() != CryptoProvider::PasswordSaltBytes
            || nonce.size() != CryptoProvider::AeadNonceBytes) {
        if (error) *error = QStringLiteral("密钥库编码或长度无效");
        return false;
    }
    QByteArray key = CryptoProvider::derivePasswordKey(password, salt, opsLimit, memLimit, error);
    if (key.size() != CryptoProvider::AeadKeyBytes) return false;
    QByteArray plainText;
    const bool decrypted = CryptoProvider::decrypt(
                cipherText, QByteArray("QTKV-V1"), nonce, key, &plainText, error);
    CryptoProvider::wipe(key);
    if (!decrypted) return false;
    const bool decoded = decodeVaultPlainText(plainText, material, error);
    CryptoProvider::wipe(plainText);
    return decoded;
}

bool KeyVault::save(const QString &path, const QByteArray &password,
                    const KeyVaultMaterial &material, QString *error)
{
    const int passwordCharacters = passwordCharacterCount(password);
    if (!material.isComplete()) {
        if (error) *error = QStringLiteral("密钥材料不完整");
        return false;
    }
    if (passwordCharacters < 10 || passwordCharacters > 1024) {
        if (error) *error = passwordCharacters < 0
                ? QStringLiteral("密钥库口令不是有效 UTF-8 文本")
                : QStringLiteral("密钥库口令必须为 10–1024 个字符");
        return false;
    }
    const QByteArray salt = CryptoProvider::randomBytes(CryptoProvider::PasswordSaltBytes, error);
    const QByteArray nonce = CryptoProvider::randomBytes(CryptoProvider::AeadNonceBytes, error);
    if (salt.size() != CryptoProvider::PasswordSaltBytes
            || nonce.size() != CryptoProvider::AeadNonceBytes) return false;
    QByteArray key = CryptoProvider::derivePasswordKey(
                password, salt, DefaultOpsLimit, DefaultMemLimit, error);
    if (key.size() != CryptoProvider::AeadKeyBytes) return false;
    QByteArray plainText = vaultPlainText(material);
    const QByteArray cipherText = CryptoProvider::encrypt(
                plainText, QByteArray("QTKV-V1"), nonce, key, error);
    CryptoProvider::wipe(plainText);
    CryptoProvider::wipe(key);
    if (cipherText.isEmpty()) return false;

    QJsonObject object;
    object.insert(QStringLiteral("magic"), QStringLiteral("QTKV"));
    object.insert(QStringLiteral("version"), 1);
    object.insert(QStringLiteral("kdf"), QStringLiteral("ARGON2ID13"));
    object.insert(QStringLiteral("opslimit"), static_cast<double>(DefaultOpsLimit));
    object.insert(QStringLiteral("memlimit"), static_cast<double>(DefaultMemLimit));
    object.insert(QStringLiteral("salt"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(salt)));
    object.insert(QStringLiteral("aead"), QStringLiteral("XCHACHA20POLY1305"));
    object.insert(QStringLiteral("nonce"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(nonce)));
    object.insert(QStringLiteral("ciphertext"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(cipherText)));
    return writeBytes(path, QJsonDocument(object).toJson(QJsonDocument::Compact), error);
}

bool KeyVault::exportRuntimeJson(const QString &path, const KeyVaultMaterial &material,
                                 QString *error)
{
    if (!material.isComplete()) {
        if (error) *error = QStringLiteral("密钥材料不完整");
        return false;
    }
    QJsonObject encryptionKeys;
    encryptionKeys.insert(material.encryptionKeyId,
                          QString::fromLatin1(LicenseCodec::base64UrlEncode(
                                                  material.productEncryptionKey)));
    QJsonObject object;
    object.insert(QStringLiteral("format"), QStringLiteral("qt-license-runtime-config"));
    object.insert(QStringLiteral("version"), 1);
    object.insert(QStringLiteral("product_id"), material.productId);
    object.insert(QStringLiteral("root_public_key"),
                  QString::fromLatin1(LicenseCodec::base64UrlEncode(material.rootPublicKey)));
    object.insert(QStringLiteral("product_decryption_keys"), encryptionKeys);
    return writeBytes(path, QJsonDocument(object).toJson(QJsonDocument::Indented), error);
}

bool KeyVault::exportRuntimeHeader(const QString &path, const KeyVaultMaterial &material,
                                   QString *error)
{
    if (!material.isComplete()) {
        if (error) *error = QStringLiteral("密钥材料不完整");
        return false;
    }
    QByteArray header;
    header.append("#ifndef QTLIC_GENERATED_RUNTIME_CONFIG_H\n");
    header.append("#define QTLIC_GENERATED_RUNTIME_CONFIG_H\n\n");
    header.append("// Generated by QtLicenseIssuer. Do not edit.\n");
    header.append("static const char QTLIC_PRODUCT_ID[] = \"");
    header.append(material.productId.toUtf8());
    header.append("\";\n");
    header.append("static const char QTLIC_ROOT_PUBLIC_KEY_B64URL[] = \"");
    header.append(LicenseCodec::base64UrlEncode(material.rootPublicKey));
    header.append("\";\n");
    header.append("static const char QTLIC_ENCRYPTION_KEY_ID[] = \"");
    header.append(material.encryptionKeyId.toUtf8());
    header.append("\";\n");
    header.append("static const char QTLIC_PRODUCT_KEY_B64URL[] = \"");
    header.append(LicenseCodec::base64UrlEncode(material.productEncryptionKey));
    header.append("\";\n\n#endif\n");
    return writeBytes(path, header, error);
}

} // namespace qtlic
