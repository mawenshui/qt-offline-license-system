#ifndef QTLIC_LICENSE_CODEC_H
#define QTLIC_LICENSE_CODEC_H

#include "license_types.h"

namespace qtlic {

class LicenseCodec
{
public:
    static QByteArray base64UrlEncode(const QByteArray &bytes);
    static bool base64UrlDecode(const QString &text, QByteArray *bytes);

    static QByteArray createIssuerCertificate(const QByteArray &rootSecretKey,
                                              const QByteArray &signingPublicKey,
                                              const QString &keyId,
                                              const QString &productId,
                                              qint64 notBeforeUtc,
                                              QString *error = nullptr);

    static bool issueToFile(const LicensePayload &payload,
                            const KeyVaultMaterial &keys,
                            const QString &outputPath,
                            QString *error = nullptr);

    static LicenseDecision verifyContainer(
            const QString &licensePath,
            const QString &expectedProductId,
            const QByteArray &rootPublicKey,
            const QHash<QString, QByteArray> &productDecryptionKeys);

    static LicenseDecision verifyFile(const VerifyOptions &options);

    static QJsonObject inspectEnvelope(const QString &licensePath, QString *error = nullptr);
};

} // namespace qtlic

#endif
