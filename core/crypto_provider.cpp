#include "crypto_provider.h"

#include <QMutex>
#include <QMutexLocker>

#include <sodium.h>

namespace qtlic {

namespace {

QMutex initMutex;
bool initialized = false;
bool initializationAttempted = false;

void setError(QString *error, const QString &message)
{
    if (error) {
        *error = message;
    }
}

} // namespace

bool CryptoProvider::initialize(QString *error)
{
    QMutexLocker locker(&initMutex);
    if (initialized) {
        return true;
    }
    if (initializationAttempted) {
        setError(error, QStringLiteral("libsodium 初始化失败"));
        return false;
    }
    initializationAttempted = true;
    if (sodium_init() < 0) {
        setError(error, QStringLiteral("libsodium 初始化失败"));
        return false;
    }
    initialized = true;
    return true;
}

QByteArray CryptoProvider::randomBytes(int size, QString *error)
{
    if (size <= 0 || !initialize(error)) {
        if (size <= 0) setError(error, QStringLiteral("随机字节长度无效"));
        return QByteArray();
    }
    QByteArray bytes(size, Qt::Uninitialized);
    randombytes_buf(bytes.data(), static_cast<size_t>(bytes.size()));
    return bytes;
}

bool CryptoProvider::generateSignKeyPair(QByteArray *publicKey, QByteArray *secretKey,
                                         QString *error)
{
    if (!publicKey || !secretKey || !initialize(error)) {
        setError(error, QStringLiteral("签名密钥输出参数无效"));
        return false;
    }
    publicKey->resize(SignPublicKeyBytes);
    secretKey->resize(SignSecretKeyBytes);
    if (crypto_sign_keypair(reinterpret_cast<unsigned char *>(publicKey->data()),
                            reinterpret_cast<unsigned char *>(secretKey->data())) != 0) {
        publicKey->clear();
        wipe(*secretKey);
        setError(error, QStringLiteral("生成 Ed25519 密钥失败"));
        return false;
    }
    return true;
}

QByteArray CryptoProvider::sign(const QByteArray &message, const QByteArray &secretKey,
                                QString *error)
{
    if (secretKey.size() != SignSecretKeyBytes || !initialize(error)) {
        setError(error, QStringLiteral("Ed25519 私钥长度无效"));
        return QByteArray();
    }
    QByteArray signature(SignatureBytes, Qt::Uninitialized);
    unsigned long long signatureLength = 0;
    if (crypto_sign_detached(
                reinterpret_cast<unsigned char *>(signature.data()), &signatureLength,
                reinterpret_cast<const unsigned char *>(message.constData()),
                static_cast<unsigned long long>(message.size()),
                reinterpret_cast<const unsigned char *>(secretKey.constData())) != 0
            || signatureLength != SignatureBytes) {
        signature.clear();
        setError(error, QStringLiteral("Ed25519 签名失败"));
    }
    return signature;
}

bool CryptoProvider::verify(const QByteArray &signature, const QByteArray &message,
                            const QByteArray &publicKey)
{
    if (signature.size() != SignatureBytes || publicKey.size() != SignPublicKeyBytes
            || !initialize()) {
        return false;
    }
    return crypto_sign_verify_detached(
                reinterpret_cast<const unsigned char *>(signature.constData()),
                reinterpret_cast<const unsigned char *>(message.constData()),
                static_cast<unsigned long long>(message.size()),
                reinterpret_cast<const unsigned char *>(publicKey.constData())) == 0;
}

QByteArray CryptoProvider::encrypt(const QByteArray &plainText, const QByteArray &aad,
                                   const QByteArray &nonce, const QByteArray &key,
                                   QString *error)
{
    if (nonce.size() != AeadNonceBytes || key.size() != AeadKeyBytes || !initialize(error)) {
        setError(error, QStringLiteral("XChaCha20 密钥或 nonce 长度无效"));
        return QByteArray();
    }
    QByteArray cipherText(plainText.size() + AeadTagBytes, Qt::Uninitialized);
    unsigned long long cipherLength = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                reinterpret_cast<unsigned char *>(cipherText.data()), &cipherLength,
                reinterpret_cast<const unsigned char *>(plainText.constData()),
                static_cast<unsigned long long>(plainText.size()),
                reinterpret_cast<const unsigned char *>(aad.constData()),
                static_cast<unsigned long long>(aad.size()),
                nullptr,
                reinterpret_cast<const unsigned char *>(nonce.constData()),
                reinterpret_cast<const unsigned char *>(key.constData())) != 0) {
        cipherText.clear();
        setError(error, QStringLiteral("XChaCha20-Poly1305 加密失败"));
        return cipherText;
    }
    cipherText.resize(static_cast<int>(cipherLength));
    return cipherText;
}

bool CryptoProvider::decrypt(const QByteArray &cipherText, const QByteArray &aad,
                             const QByteArray &nonce, const QByteArray &key,
                             QByteArray *plainText, QString *error)
{
    if (!plainText || cipherText.size() < AeadTagBytes || nonce.size() != AeadNonceBytes
            || key.size() != AeadKeyBytes || !initialize(error)) {
        setError(error, QStringLiteral("XChaCha20 解密参数无效"));
        return false;
    }
    QByteArray output(cipherText.size() - AeadTagBytes, Qt::Uninitialized);
    unsigned long long plainLength = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                reinterpret_cast<unsigned char *>(output.data()), &plainLength, nullptr,
                reinterpret_cast<const unsigned char *>(cipherText.constData()),
                static_cast<unsigned long long>(cipherText.size()),
                reinterpret_cast<const unsigned char *>(aad.constData()),
                static_cast<unsigned long long>(aad.size()),
                reinterpret_cast<const unsigned char *>(nonce.constData()),
                reinterpret_cast<const unsigned char *>(key.constData())) != 0) {
        wipe(output);
        setError(error, QStringLiteral("XChaCha20-Poly1305 认证或解密失败"));
        return false;
    }
    output.resize(static_cast<int>(plainLength));
    *plainText = output;
    return true;
}

QByteArray CryptoProvider::derivePasswordKey(const QByteArray &password, const QByteArray &salt,
                                             quint64 opsLimit, quint64 memLimit, QString *error)
{
    if (password.isEmpty() || salt.size() != PasswordSaltBytes || !initialize(error)) {
        setError(error, QStringLiteral("密钥库口令或 salt 无效"));
        return QByteArray();
    }
    QByteArray key(AeadKeyBytes, Qt::Uninitialized);
    if (crypto_pwhash(reinterpret_cast<unsigned char *>(key.data()),
                      static_cast<unsigned long long>(key.size()),
                      password.constData(), static_cast<unsigned long long>(password.size()),
                      reinterpret_cast<const unsigned char *>(salt.constData()),
                      static_cast<unsigned long long>(opsLimit), static_cast<size_t>(memLimit),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        wipe(key);
        setError(error, QStringLiteral("Argon2id 密钥派生失败，可能内存不足"));
        return QByteArray();
    }
    return key;
}

QByteArray CryptoProvider::keyedHash(const QByteArray &message, const QByteArray &key,
                                     int outputBytes, QString *error)
{
    if (key.isEmpty() || outputBytes < static_cast<int>(crypto_generichash_BYTES_MIN)
            || outputBytes > static_cast<int>(crypto_generichash_BYTES_MAX)
            || !initialize(error)) {
        setError(error, QStringLiteral("BLAKE2b 参数无效"));
        return QByteArray();
    }
    QByteArray output(outputBytes, Qt::Uninitialized);
    if (crypto_generichash(
                reinterpret_cast<unsigned char *>(output.data()),
                static_cast<size_t>(output.size()),
                reinterpret_cast<const unsigned char *>(message.constData()),
                static_cast<unsigned long long>(message.size()),
                reinterpret_cast<const unsigned char *>(key.constData()),
                static_cast<size_t>(key.size())) != 0) {
        output.clear();
        setError(error, QStringLiteral("BLAKE2b 计算失败"));
    }
    return output;
}

bool CryptoProvider::lockMemory(QByteArray &bytes, QString *error)
{
    if (bytes.isEmpty() || !initialize(error)) {
        setError(error, QStringLiteral("敏感内存为空或密码库不可用"));
        return false;
    }
    bytes.detach();
    if (sodium_mlock(bytes.data(), static_cast<size_t>(bytes.size())) != 0) {
        setError(error, QStringLiteral("无法锁定敏感密钥内存"));
        return false;
    }
    return true;
}

void CryptoProvider::wipeLocked(QByteArray &bytes)
{
    if (!bytes.isEmpty()) {
        sodium_memzero(bytes.data(), static_cast<size_t>(bytes.size()));
        sodium_munlock(bytes.data(), static_cast<size_t>(bytes.size()));
        bytes.clear();
    }
}

void CryptoProvider::wipe(QByteArray &bytes)
{
    if (!bytes.isEmpty()) {
        sodium_memzero(bytes.data(), static_cast<size_t>(bytes.size()));
        bytes.clear();
    }
}

} // namespace qtlic
