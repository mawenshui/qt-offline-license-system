#ifndef QTLIC_HARDWARE_FINGERPRINT_H
#define QTLIC_HARDWARE_FINGERPRINT_H

#include "license_types.h"

#include <QJsonObject>

namespace qtlic {

class HardwareFingerprint
{
public:
    static QString slotDisplayName(const QString &slot);
    static QString typeDisplayName(const QString &type);
    static QString normalize(const QString &type, const QString &value);
    static bool isUsable(const QString &type, const QString &value, QString *reason = nullptr);
    static QString hash(const QString &type, const QString &value);
    static QVector<HardwareValue> collect(QStringList *warnings = nullptr);
    static HardwareBinding bindingFromValues(const QVector<HardwareValue> &values,
                                             const QString &mode, int minimum,
                                             QString *error = nullptr);
    static bool matches(const HardwareBinding &binding, const QVector<HardwareValue> &actual,
                        int *matchedSlots = nullptr);
    static QJsonObject requestToJson(const QString &productId,
                                     const QVector<HardwareValue> &values);
    static bool requestFromJson(const QJsonObject &object, QString *productId,
                                QVector<HardwareValue> *values, QString *error = nullptr);
};

} // namespace qtlic

#endif
