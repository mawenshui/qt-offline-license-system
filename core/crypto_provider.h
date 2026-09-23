#ifndef QTLIC_CRYPTO_PROVIDER_H
#define QTLIC_CRYPTO_PROVIDER_H

#include <QByteArray>
#include <QString>

namespace qtlic {

class CryptoProvider
{
public:
    enum {
        SignPublicKeyBytes = 32,
        SignSecretKeyBytes = 64,
        SignatureBytes = 64,
        AeadKeyBytes = 32,
        AeadNonceBytes = 24,
        AeadTagBytes = 16,
        PasswordSaltBytes = 16
    };

    static bool initialize(QString *error = nullptr);
    static QByteArray randomBytes(int size, QString *error = nullptr);
    static bool generateSignKeyPair(QByteArray *publicKey, QByteArray *secretKey,
                                    QString *error = nullptr);
    static QByteArray sign(const QByteArray &message, const QByteArray &secretKey,
                           QString *error = nullptr);
    static bool verify(const QByteArray &signature, const QByteArray &message,
                       const QByteArray &publicKey);
    static QByteArray encrypt(const QByteArray &plainText, const QByteArray &aad,
                              const QByteArray &nonce, const QByteArray &key,
                              QString *error = nullptr);
    static bool decrypt(const QByteArray &cipherText, const QByteArray &aad,
                        const QByteArray &nonce, const QByteArray &key,
                        QByteArray *plainText, QString *error = nullptr);
    static QByteArray derivePasswordKey(const QByteArray &password, const QByteArray &salt,
                                        quint64 opsLimit, quint64 memLimit,
                                        QString *error = nullptr);
    static QByteArray keyedHash(const QByteArray &message, const QByteArray &key,
                                int outputBytes = 32, QString *error = nullptr);
    static bool lockMemory(QByteArray &bytes, QString *error = nullptr);
    static void wipeLocked(QByteArray &bytes);
    static void wipe(QByteArray &bytes);
};

} // namespace qtlic

#endif
