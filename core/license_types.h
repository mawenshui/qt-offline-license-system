#ifndef QTLIC_LICENSE_TYPES_H
#define QTLIC_LICENSE_TYPES_H

#include <QHash>
#include <QJsonObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

namespace qtlic {

enum class LicenseMode {
    Perpetual,
    FixedExpiry,
    ValidityDuration,
    RuntimeQuota,
    Hybrid
};

enum class LicenseStatus {
    Valid,
    FileMissing,
    FileTooLarge,
    MalformedContainer,
    UnsupportedVersion,
    UnknownSigningKey,
    IssuerCertificateInvalid,
    SignatureInvalid,
    UnknownEncryptionKey,
    DecryptionFailed,
    MalformedPayload,
    ProductMismatch,
    HardwareUnavailable,
    HardwareMismatch,
    NotYetValid,
    Expired,
    RuntimeQuotaExceeded,
    ClockRollbackDetected,
    ClockAnomaly,
    StateRollbackDetected,
    StateCorrupt,
    CryptoUnavailable,
    IoError,
    InternalError
};

struct HardwareValue {
    QString slot;
    QString type;
    QString value;
    QString hash;
    QString displayHint;
};

struct BindingSlot {
    QString slot;
    QString type;
    QStringList acceptedHashes;
};

struct HardwareBinding {
    QString mode = QStringLiteral("all");
    int minimum = 0;
    QVector<BindingSlot> bindingSlots;
};

struct LicensePayload {
    int version = 1;
    QString licenseId;
    QString productId;
    QString customerId;
    QString customerName;
    QString orderId;
    qint64 issuedAt = 0;
    LicenseMode licenseMode = LicenseMode::Perpetual;
    qint64 notBefore = -1;
    qint64 expiresAt = -1;
    qint64 maxRuntimeSeconds = -1;
    int stateEpoch = 1;
    int fingerprintVersion = 1;
    HardwareBinding binding;
    QStringList features;
    QString issuer;
    QString note;
};

struct KeyVaultMaterial {
    int version = 1;
    QString productId;
    QString keyId;
    QString encryptionKeyId;
    QByteArray rootPublicKey;
    QByteArray rootSecretKey;
    QByteArray signingPublicKey;
    QByteArray signingSecretKey;
    QByteArray productEncryptionKey;
    QByteArray issuerCertificate;
    bool secretsMemoryLocked = false;

    bool isComplete() const;
    void clearSecrets();
};

struct VerifyOptions {
    QString productId;
    QString licensePath;
    QByteArray rootPublicKey;
    QHash<QString, QByteArray> productDecryptionKeys;
    QVector<HardwareValue> hardware;
    QString stateDirectory;
    qint64 nowUtcOverride = -1;
    bool requireHardwareBinding = true;
};

struct LicenseDecision {
    LicenseStatus status = LicenseStatus::InternalError;
    QString message;
    QString signingKeyId;
    QString encryptionKeyId;
    LicensePayload payload;
    QSet<QString> features;
    qint64 effectiveUtc = 0;

    bool valid() const { return status == LicenseStatus::Valid; }
    bool hasFeature(const QString &feature) const { return valid() && features.contains(feature); }
};

QString licenseModeToString(LicenseMode mode);
bool licenseModeFromString(const QString &text, LicenseMode *mode);
QString licenseStatusToString(LicenseStatus status);

QJsonObject licensePayloadToJson(const LicensePayload &payload);
bool licensePayloadFromJson(const QJsonObject &object, LicensePayload *payload, QString *error);
bool validateLicensePayload(const LicensePayload &payload, QString *error);

} // namespace qtlic

#endif
