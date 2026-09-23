#ifndef QTLIC_AUDIT_LOGGER_H
#define QTLIC_AUDIT_LOGGER_H

#include <QString>

namespace qtlic {

struct AuditEvent {
    QString action;
    QString outcome;
    QString productId;
    QString subjectId;
    QString filePath;
    QString message;
};

class AuditLogger
{
public:
    static QString defaultLogPath();
    static QString fileSha256(const QString &path, QString *error = nullptr);
    static bool append(const AuditEvent &event, const QString &logPath = QString(),
                       QString *error = nullptr);
    static bool verify(const QString &logPath, int *recordCount = nullptr,
                       QString *error = nullptr);
};

} // namespace qtlic

#endif
