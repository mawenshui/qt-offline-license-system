#ifndef QTLIC_LICENSE_RUNTIME_H
#define QTLIC_LICENSE_RUNTIME_H

#include "license_types.h"

#include <QElapsedTimer>

namespace qtlic {

class LicenseRuntimeSession
{
public:
    LicenseRuntimeSession();
    ~LicenseRuntimeSession();

    LicenseRuntimeSession(const LicenseRuntimeSession &) = delete;
    LicenseRuntimeSession &operator=(const LicenseRuntimeSession &) = delete;

    LicenseDecision start(const VerifyOptions &options);
    LicenseDecision checkpoint(qint64 nowUtcOverride = -1);

    bool isActive() const { return m_active; }
    const LicenseDecision &decision() const { return m_decision; }

private:
    LicenseDecision m_decision;
    QByteArray m_productKey;
    QString m_stateDirectory;
    QElapsedTimer m_elapsed;
    qint64 m_committedElapsedMs = 0;
    bool m_active = false;
};

} // namespace qtlic

#endif
