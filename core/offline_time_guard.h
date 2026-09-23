#ifndef QTLIC_OFFLINE_TIME_GUARD_H
#define QTLIC_OFFLINE_TIME_GUARD_H

#include "license_types.h"

namespace qtlic {

class OfflineTimeGuard
{
public:
    static LicenseStatus evaluate(const LicensePayload &payload,
                                  const QByteArray &productKey,
                                  const QString &stateDirectory,
                                  qint64 nowUtc,
                                  qint64 runtimeDeltaSeconds,
                                  qint64 *effectiveUtc,
                                  QString *error = nullptr);
};

} // namespace qtlic

#endif
