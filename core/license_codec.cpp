#include "license_codec.h"

#include "crypto_provider.h"
#include "hardware_fingerprint.h"
#include "offline_time_guard.h"

#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUuid>

namespace qtlic {

namespace {

const qint64 MaxContainerBytes = 256 * 1024;
const int MaxPayloadBytes = 64 * 1024;

void appendU32(QByteArray *output, quint32 value)
{
    output->append(static_cast<char>((value >> 24) & 0xff));
    output->append(static_cast<char>((value >> 16) & 0xff));
    output->append(static_cast<char>((value >> 8) & 0xff));
    output->append(static_cast<char>(value & 0xff));
}

void appendLp(QByteArray *output, const QByteArray &value)
{
    appendU32(output, static_cast<quint32>(value.size()));
    output->append(value);
}

QByteArray versionBytes(int version)
{
    QByteArray bytes;
    bytes.append(static_cast<char>((version >> 8) & 0xff));
    bytes.append(static_cast<char>(version & 0xff));
    return bytes;
}

QByteArray makeAad(int version, const QString &suite, const QString &keyId,
                   const QString &encryptionKeyId, const QByteArray &certificate)
{
    QByteArray aad("QTLIC-AAD-V1", 13);
    aad.append('\0');
    appendLp(&aad, versionBytes(version));
    appendLp(&aad, suite.toUtf8());
    appendLp(&aad, keyId.toUtf8());
    appendLp(&aad, encryptionKeyId.toUtf8());
    appendLp(&aad, certificate);
    return aad;
}

QByteArray makeSignatureTranscript(int version, const QString &suite, const QString &keyId,
                                   const QString &encryptionKeyId,
                                   const QByteArray &certificate, const QByteArray &nonce,
                                   const QByteArray &cipherText)
{
    QByteArray transcript("QTLIC-SIG-V1", 13);
    transcript.append('\0');
    appendLp(&transcript, versionBytes(version));
    appendLp(&transcript, suite.toUtf8());
    appendLp(&transcript, keyId.toUtf8());
    appendLp(&transcript, encryptionKeyId.toUtf8());
    appendLp(&transcript, certificate);
    appendLp(&transcript, nonce);
    appendLp(&transcript, cipherText);
    return transcript;
}

LicenseDecision failure(LicenseStatus status, const QString &message)
{
    LicenseDecision decision;
    decision.status = status;
    decision.message = message;
    return decision;
}

bool parseJsonObject(const QByteArray &bytes, QJsonObject *object, QString *error)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("JSON 解析失败: %1").arg(parseError.errorString());
        return false;
    }
    *object = document.object();
    return true;
}

bool readContainer(const QString &path, QByteArray *bytes, QString *error)
{
    QFile file(path);
    if (!file.exists()) {
        if (error) *error = QStringLiteral("授权文件不存在");
        return false;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("授权文件无法读取");
        return false;
    }
    if (file.size() <= 0 || file.size() > MaxContainerBytes) {
        if (error) *error = QStringLiteral("授权文件大小无效");
        return false;
    }
    *bytes = file.readAll();
    return true;
}

bool validateIssuerCertificate(const QByteArray &certificateBytes,
                               const QByteArray &rootPublicKey,
                               const QString &expectedKeyId,
                               const QString &expectedProductId,
                               qint64 issuedAt,
                               QByteArray *signingPublicKey,
                               QString *error,
                               bool *productMismatch = nullptr)
{
    if (productMismatch) *productMismatch = false;
    QJsonObject envelope;
    if (!parseJsonObject(certificateBytes, &envelope, error)) return false;
    QByteArray body;
    QByteArray signature;
    if (!LicenseCodec::base64UrlDecode(envelope.value(QStringLiteral("body")).toString(), &body)
            || !LicenseCodec::base64UrlDecode(
                envelope.value(QStringLiteral("signature")).toString(), &signature)) {
        if (error) *error = QStringLiteral("签发证书 Base64Url 无效");
        return false;
    }
    QByteArray transcript("QTLIC-ISSUER-CERT-V1", 20);
    transcript.append('\0');
    transcript.append(body);
    if (!CryptoProvider::verify(signature, transcript, rootPublicKey)) {
        if (error) *error = QStringLiteral("签发证书根签名无效");
        return false;
    }

    QJsonObject certificate;
    if (!parseJsonObject(body, &certificate, error)) return false;
    if (certificate.value(QStringLiteral("schema")).toString()
            != QLatin1String("qt-license-issuer-certificate")
            || certificate.value(QStringLiteral("version")).toInt(-1) != 1
            || certificate.value(QStringLiteral("usage")).toString()
            != QLatin1String("license-signing")
            || certificate.value(QStringLiteral("kid")).toString() != expectedKeyId) {
        if (error) *error = QStringLiteral("签发证书字段无效");
        return false;
    }
    const QJsonArray products = certificate.value(QStringLiteral("product_ids")).toArray();
    bool productAllowed = false;
    for (const QJsonValue &product : products) {
        if (product.toString() == expectedProductId) productAllowed = true;
    }
    if (!productAllowed) {
        if (productMismatch) *productMismatch = true;
        if (error) *error = QStringLiteral("签发证书不允许该产品");
        return false;
    }
    const qint64 notBefore = static_cast<qint64>(
                certificate.value(QStringLiteral("not_before")).toDouble(-1));
    const QJsonValue notAfterValue = certificate.value(QStringLiteral("not_after"));
    const qint64 notAfter = notAfterValue.isNull() ? -1
            : static_cast<qint64>(notAfterValue.toDouble(-1));
    if (notBefore <= 0
            || (issuedAt >= 0
                && (issuedAt < notBefore || (notAfter >= 0 && issuedAt >= notAfter)))) {
        if (error) *error = QStringLiteral("授权签发时间不在证书有效范围内");
        return false;
    }
    QByteArray publicKey;
    if (!LicenseCodec::base64UrlDecode(
                certificate.value(QStringLiteral("public_key")).toString(), &publicKey)
            || publicKey.size() != CryptoProvider::SignPublicKeyBytes) {
        if (error) *error = QStringLiteral("签发证书公钥无效");
        return false;
    }
    *signingPublicKey = publicKey;
    return true;
}

} // namespace

QByteArray LicenseCodec::base64UrlEncode(const QByteArray &bytes)
{
    return bytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

bool LicenseCodec::base64UrlDecode(const QString &text, QByteArray *bytes)
{
    if (!bytes || text.isEmpty() || text.contains(QLatin1Char('='))
            || !QRegularExpression(QStringLiteral("^[A-Za-z0-9_-]+$")).match(text).hasMatch()) {
        return false;
    }
    const QByteArray decoded = QByteArray::fromBase64(text.toLatin1(), QByteArray::Base64UrlEncoding);
    if (decoded.isEmpty() || base64UrlEncode(decoded) != text.toLatin1()) return false;
    *bytes = decoded;
    return true;
}

QByteArray LicenseCodec::createIssuerCertificate(const QByteArray &rootSecretKey,
                                                 const QByteArray &signingPublicKey,
                                                 const QString &keyId,
                                                 const QString &productId,
                                                 qint64 notBeforeUtc,
                                                 QString *error)
{
    if (rootSecretKey.size() != CryptoProvider::SignSecretKeyBytes
            || signingPublicKey.size() != CryptoProvider::SignPublicKeyBytes
            || keyId.isEmpty() || productId.isEmpty() || notBeforeUtc <= 0) {
        if (error) *error = QStringLiteral("签发证书输入参数无效");
        return QByteArray();
    }
    QJsonArray products;
    products.append(productId);
    QJsonObject bodyObject;
    bodyObject.insert(QStringLiteral("schema"), QStringLiteral("qt-license-issuer-certificate"));
    bodyObject.insert(QStringLiteral("version"), 1);
    bodyObject.insert(QStringLiteral("kid"), keyId);
    bodyObject.insert(QStringLiteral("public_key"),
                      QString::fromLatin1(base64UrlEncode(signingPublicKey)));
    bodyObject.insert(QStringLiteral("product_ids"), products);
    bodyObject.insert(QStringLiteral("usage"), QStringLiteral("license-signing"));
    bodyObject.insert(QStringLiteral("not_before"), static_cast<double>(notBeforeUtc));
    bodyObject.insert(QStringLiteral("not_after"), QJsonValue(QJsonValue::Null));
    const QByteArray body = QJsonDocument(bodyObject).toJson(QJsonDocument::Compact);

    QByteArray transcript("QTLIC-ISSUER-CERT-V1", 20);
    transcript.append('\0');
    transcript.append(body);
    const QByteArray signature = CryptoProvider::sign(transcript, rootSecretKey, error);
    if (signature.size() != CryptoProvider::SignatureBytes) return QByteArray();

    QJsonObject envelope;
    envelope.insert(QStringLiteral("body"), QString::fromLatin1(base64UrlEncode(body)));
    envelope.insert(QStringLiteral("signature"), QString::fromLatin1(base64UrlEncode(signature)));
    return QJsonDocument(envelope).toJson(QJsonDocument::Compact);
}

bool LicenseCodec::issueToFile(const LicensePayload &payload, const KeyVaultMaterial &keys,
                               const QString &outputPath, QString *error)
{
    if (!CryptoProvider::initialize(error)) return false;
    if (!keys.isComplete() || payload.productId != keys.productId) {
        if (error) *error = QStringLiteral("密钥库不完整或产品不匹配");
        return false;
    }
    if (QFileInfo::exists(outputPath)) {
        if (error) *error = QStringLiteral("输出文件已存在，拒绝覆盖");
        return false;
    }
    if (!validateLicensePayload(payload, error)) return false;
    const QByteArray plainText = QJsonDocument(licensePayloadToJson(payload))
            .toJson(QJsonDocument::Compact);
    if (plainText.size() > MaxPayloadBytes) {
        if (error) *error = QStringLiteral("授权载荷超过 64 KiB");
        return false;
    }

    const QString suite = QStringLiteral("ED25519+XCHACHA20POLY1305");
    const QByteArray nonce = CryptoProvider::randomBytes(CryptoProvider::AeadNonceBytes, error);
    if (nonce.size() != CryptoProvider::AeadNonceBytes) return false;
    const QByteArray aad = makeAad(1, suite, keys.keyId, keys.encryptionKeyId,
                                   keys.issuerCertificate);
    const QByteArray cipherText = CryptoProvider::encrypt(
                plainText, aad, nonce, keys.productEncryptionKey, error);
    if (cipherText.isEmpty()) return false;
    const QByteArray transcript = makeSignatureTranscript(
                1, suite, keys.keyId, keys.encryptionKeyId, keys.issuerCertificate,
                nonce, cipherText);
    const QByteArray signature = CryptoProvider::sign(transcript, keys.signingSecretKey, error);
    if (signature.size() != CryptoProvider::SignatureBytes) return false;

    QJsonObject envelope;
    envelope.insert(QStringLiteral("magic"), QStringLiteral("QTLIC"));
    envelope.insert(QStringLiteral("container_version"), 1);
    envelope.insert(QStringLiteral("suite"), suite);
    envelope.insert(QStringLiteral("kid"), keys.keyId);
    envelope.insert(QStringLiteral("ekid"), keys.encryptionKeyId);
    envelope.insert(QStringLiteral("issuer_certificate"),
                    QString::fromLatin1(base64UrlEncode(keys.issuerCertificate)));
    envelope.insert(QStringLiteral("nonce"), QString::fromLatin1(base64UrlEncode(nonce)));
    envelope.insert(QStringLiteral("ciphertext"), QString::fromLatin1(base64UrlEncode(cipherText)));
    envelope.insert(QStringLiteral("signature"), QString::fromLatin1(base64UrlEncode(signature)));
    const QByteArray container = QJsonDocument(envelope).toJson(QJsonDocument::Compact);

    const QString temporaryPath = outputPath + QStringLiteral(".tmp-")
            + QUuid::createUuid().toString(QUuid::WithoutBraces);
    QFile file(temporaryPath);
    const bool written = file.open(QIODevice::WriteOnly | QIODevice::NewOnly)
            && file.write(container) == container.size() && file.flush();
    file.close();
    if (!written || !QFile::rename(temporaryPath, outputPath)) {
        QFile::remove(temporaryPath);
        if (error) *error = QStringLiteral("授权文件写入失败");
        return false;
    }

    QHash<QString, QByteArray> encryptionKeys;
    encryptionKeys.insert(keys.encryptionKeyId, keys.productEncryptionKey);
    const LicenseDecision selfCheck = verifyContainer(
                outputPath, payload.productId, keys.rootPublicKey, encryptionKeys);
    if (!selfCheck.valid()
            || licensePayloadToJson(selfCheck.payload) != licensePayloadToJson(payload)) {
        QFile::remove(outputPath);
        if (error) *error = QStringLiteral("生成后自验证失败: %1").arg(selfCheck.message);
        return false;
    }
    return true;
}

LicenseDecision LicenseCodec::verifyContainer(
        const QString &licensePath, const QString &expectedProductId,
        const QByteArray &rootPublicKey,
        const QHash<QString, QByteArray> &productDecryptionKeys)
{
    if (!CryptoProvider::initialize()) {
        return failure(LicenseStatus::CryptoUnavailable, QStringLiteral("libsodium 不可用"));
    }
    if (rootPublicKey.size() != CryptoProvider::SignPublicKeyBytes) {
        return failure(LicenseStatus::IssuerCertificateInvalid, QStringLiteral("根公钥长度无效"));
    }
    QByteArray fileBytes;
    QString error;
    if (!readContainer(licensePath, &fileBytes, &error)) {
        const QFileInfo info(licensePath);
        LicenseStatus status = LicenseStatus::IoError;
        if (!info.exists()) status = LicenseStatus::FileMissing;
        else if (info.size() <= 0) status = LicenseStatus::MalformedContainer;
        else if (info.size() > MaxContainerBytes) status = LicenseStatus::FileTooLarge;
        return failure(status, error);
    }
    QJsonObject envelope;
    if (!parseJsonObject(fileBytes, &envelope, &error)) {
        return failure(LicenseStatus::MalformedContainer, error);
    }
    const int version = envelope.value(QStringLiteral("container_version")).toInt(-1);
    const QString suite = envelope.value(QStringLiteral("suite")).toString();
    const QString keyId = envelope.value(QStringLiteral("kid")).toString();
    const QString encryptionKeyId = envelope.value(QStringLiteral("ekid")).toString();
    if (envelope.value(QStringLiteral("magic")).toString() != QLatin1String("QTLIC")
            || version != 1 || suite != QLatin1String("ED25519+XCHACHA20POLY1305")
            || keyId.isEmpty() || encryptionKeyId.isEmpty()) {
        const bool explicitUnsupportedVersion = envelope.value(
                    QStringLiteral("container_version")).isDouble() && version != 1;
        return failure(explicitUnsupportedVersion ? LicenseStatus::UnsupportedVersion
                                                  : LicenseStatus::MalformedContainer,
                       QStringLiteral("授权容器头无效或版本不支持"));
    }

    QByteArray certificate;
    QByteArray nonce;
    QByteArray cipherText;
    QByteArray signature;
    if (!base64UrlDecode(envelope.value(QStringLiteral("issuer_certificate")).toString(), &certificate)
            || !base64UrlDecode(envelope.value(QStringLiteral("nonce")).toString(), &nonce)
            || !base64UrlDecode(envelope.value(QStringLiteral("ciphertext")).toString(), &cipherText)
            || !base64UrlDecode(envelope.value(QStringLiteral("signature")).toString(), &signature)
            || nonce.size() != CryptoProvider::AeadNonceBytes
            || signature.size() != CryptoProvider::SignatureBytes
            || cipherText.size() < CryptoProvider::AeadTagBytes) {
        return failure(LicenseStatus::MalformedContainer, QStringLiteral("授权容器编码或长度无效"));
    }

    QByteArray signingPublicKey;
    bool certificateProductMismatch = false;
    if (!validateIssuerCertificate(certificate, rootPublicKey, keyId, expectedProductId,
                                   -1, &signingPublicKey, &error,
                                   &certificateProductMismatch)) {
        return failure(certificateProductMismatch ? LicenseStatus::ProductMismatch
                                                   : LicenseStatus::IssuerCertificateInvalid,
                       certificateProductMismatch
                       ? QStringLiteral("授权产品不匹配") : error);
    }
    const QByteArray transcript = makeSignatureTranscript(
                version, suite, keyId, encryptionKeyId, certificate, nonce, cipherText);
    if (!CryptoProvider::verify(signature, transcript, signingPublicKey)) {
        return failure(LicenseStatus::SignatureInvalid, QStringLiteral("授权签名无效"));
    }

    const QByteArray productKey = productDecryptionKeys.value(encryptionKeyId);
    if (productKey.size() != CryptoProvider::AeadKeyBytes) {
        return failure(LicenseStatus::UnknownEncryptionKey,
                       QStringLiteral("找不到产品解密密钥: %1").arg(encryptionKeyId));
    }
    const QByteArray aad = makeAad(version, suite, keyId, encryptionKeyId, certificate);
    QByteArray plainText;
    if (!CryptoProvider::decrypt(cipherText, aad, nonce, productKey, &plainText, &error)) {
        return failure(LicenseStatus::DecryptionFailed, error);
    }
    if (plainText.size() > MaxPayloadBytes) {
        CryptoProvider::wipe(plainText);
        return failure(LicenseStatus::MalformedPayload, QStringLiteral("授权载荷过大"));
    }
    QJsonObject payloadObject;
    if (!parseJsonObject(plainText, &payloadObject, &error)) {
        CryptoProvider::wipe(plainText);
        return failure(LicenseStatus::MalformedPayload, error);
    }
    CryptoProvider::wipe(plainText);
    LicensePayload payload;
    if (!licensePayloadFromJson(payloadObject, &payload, &error)) {
        return failure(LicenseStatus::MalformedPayload, error);
    }
    if (payload.productId != expectedProductId) {
        return failure(LicenseStatus::ProductMismatch, QStringLiteral("授权产品不匹配"));
    }

    if (!validateIssuerCertificate(certificate, rootPublicKey, keyId, payload.productId,
                                   payload.issuedAt, &signingPublicKey, &error)) {
        return failure(LicenseStatus::IssuerCertificateInvalid, error);
    }

    LicenseDecision decision;
    decision.status = LicenseStatus::Valid;
    decision.message = QStringLiteral("授权容器有效");
    decision.signingKeyId = keyId;
    decision.encryptionKeyId = encryptionKeyId;
    decision.payload = payload;
    for (const QString &feature : payload.features) decision.features.insert(feature);
    return decision;
}

LicenseDecision LicenseCodec::verifyFile(const VerifyOptions &options)
{
    LicenseDecision decision = verifyContainer(options.licensePath, options.productId,
                                               options.rootPublicKey,
                                               options.productDecryptionKeys);
    if (!decision.valid()) return decision;

    QVector<HardwareValue> hardware = options.hardware;
    if (hardware.isEmpty()) hardware = HardwareFingerprint::collect();
    if (options.requireHardwareBinding && hardware.isEmpty()) {
        decision.status = LicenseStatus::HardwareUnavailable;
        decision.message = QStringLiteral("无法获取硬件信息");
        return decision;
    }
    if (options.requireHardwareBinding
            && !HardwareFingerprint::matches(decision.payload.binding, hardware)) {
        decision.status = LicenseStatus::HardwareMismatch;
        decision.message = QStringLiteral("硬件指纹不匹配");
        return decision;
    }

    const QByteArray productKey = options.productDecryptionKeys.value(decision.encryptionKeyId);
    const qint64 nowUtc = options.nowUtcOverride > 0
            ? options.nowUtcOverride : QDateTime::currentSecsSinceEpoch();
    QString timeError;
    const LicenseStatus timeStatus = OfflineTimeGuard::evaluate(
                decision.payload, productKey, options.stateDirectory, nowUtc, 0,
                &decision.effectiveUtc, &timeError);
    if (timeStatus != LicenseStatus::Valid) {
        decision.status = timeStatus;
        decision.message = timeError.isEmpty() ? licenseStatusToString(timeStatus) : timeError;
        return decision;
    }
    decision.message = QStringLiteral("授权有效");
    return decision;
}

QJsonObject LicenseCodec::inspectEnvelope(const QString &licensePath, QString *error)
{
    QByteArray bytes;
    if (!readContainer(licensePath, &bytes, error)) return QJsonObject();
    QJsonObject object;
    if (!parseJsonObject(bytes, &object, error)) return QJsonObject();
    return object;
}

} // namespace qtlic
