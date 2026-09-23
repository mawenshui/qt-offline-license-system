#ifndef QTLIC_RUNTIME_COMPATIBILITY_H
#define QTLIC_RUNTIME_COMPATIBILITY_H

#include "license_types.h"

#include <QString>

namespace qtlic {

struct RuntimeCompatibilityResult {
    bool compatible = false;
    QString minimumVersion;
    QString message;
};

class RuntimeCompatibility
{
public:
    static RuntimeCompatibilityResult check(const QString &targetRuntimeSeries,
                                            const LicensePayload &payload);
};

} // namespace qtlic

#endif
