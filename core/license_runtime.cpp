#include "license_runtime.h"

#include "crypto_provider.h"
#include "license_codec.h"
#include "offline_time_guard.h"

#include <QDateTime>

namespace qtlic {

LicenseRuntimeSession::LicenseRuntimeSession() = default;

LicenseRuntimeSession::~LicenseRuntimeSession()
{
    CryptoProvider::wipe(m_productKey);
}

LicenseDecision LicenseRuntimeSession::start(const VerifyOptions &options)
{
    CryptoProvider::wipe(m_productKey);
    m_active = false;
    m_committedElapsedMs = 0;
    m_decision = LicenseCodec::verifyFile(options);
    if (!m_decision.valid()) return m_decision;

    m_productKey = options.productDecryptionKeys.value(m_decision.encryptionKeyId);
    if (m_productKey.size() != 32) {
        m_decision.status = LicenseStatus::UnknownEncryptionKey;
        m_decision.message = QStringLiteral("运行期授权密钥不可用");
        CryptoProvider::wipe(m_productKey);
        return m_decision;
    }

    m_stateDirectory = options.stateDirectory;
    m_elapsed.start();
    m_active = true;
    return m_decision;
}

LicenseDecision LicenseRuntimeSession::checkpoint(qint64 nowUtcOverride)
{
    if (!m_active) return m_decision;

    const qint64 elapsedMs = m_elapsed.elapsed();
    const qint64 deltaSeconds = qMax<qint64>(0, (elapsedMs - m_committedElapsedMs) / 1000);
    const qint64 nowUtc = nowUtcOverride > 0
            ? nowUtcOverride : QDateTime::currentSecsSinceEpoch();

    QString error;
    const LicenseStatus status = OfflineTimeGuard::evaluate(
                m_decision.payload, m_productKey, m_stateDirectory, nowUtc,
                deltaSeconds, &m_decision.effectiveUtc, &error);
    m_decision.status = status;
    m_decision.message = status == LicenseStatus::Valid
            ? QStringLiteral("授权有效")
            : (error.isEmpty() ? licenseStatusToString(status) : error);
    m_committedElapsedMs += deltaSeconds * 1000;
    if (status != LicenseStatus::Valid) m_active = false;
    return m_decision;
}

} // namespace qtlic
