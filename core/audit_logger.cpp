#include "audit_logger.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>

namespace qtlic {
namespace {

QByteArray recordBytes(const QJsonObject &record)
{
    return QJsonDocument(record).toJson(QJsonDocument::Compact);
}

QString recordHash(const QJsonObject &record)
{
    return QString::fromLatin1(QCryptographicHash::hash(
                                   recordBytes(record), QCryptographicHash::Sha256).toHex());
}

bool verifyInternal(const QString &path, int *recordCount, QString *lastHash,
                    QString *error)
{
    if (recordCount) *recordCount = 0;
    if (lastHash) lastHash->clear();
    QFile file(path);
    if (!file.exists()) return true;
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("无法读取审计日志：%1").arg(file.errorString());
        return false;
    }
    QString previous;
    int count = 0;
    int lineNumber = 0;
    while (!file.atEnd()) {
        const QByteArray line = file.readLine().trimmed();
        ++lineNumber;
        if (line.isEmpty()) continue;
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(line, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            if (error) *error = QStringLiteral("审计日志第 %1 行格式无效").arg(lineNumber);
            return false;
        }
        QJsonObject object = document.object();
        const QString storedHash = object.take(QStringLiteral("record_hash")).toString();
        if (storedHash.isEmpty()
                || object.value(QStringLiteral("previous_hash")).toString() != previous
                || recordHash(object) != storedHash) {
            if (error) *error = QStringLiteral("审计日志第 %1 行哈希链校验失败").arg(lineNumber);
            return false;
        }
        previous = storedHash;
        ++count;
    }
    if (recordCount) *recordCount = count;
    if (lastHash) *lastHash = previous;
    return true;
}

QString actorName()
{
    QString actor = qEnvironmentVariable("USERNAME");
    if (actor.isEmpty()) actor = qEnvironmentVariable("USER");
    return actor.isEmpty() ? QStringLiteral("unknown-local-user") : actor.left(256);
}

} // namespace

QString AuditLogger::defaultLogPath()
{
    const QString root = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    return QDir(root).filePath(QStringLiteral("audit/audit-%1.jsonl")
                               .arg(QDate::currentDate().toString(QStringLiteral("yyyy-MM"))));
}

QString AuditLogger::fileSha256(const QString &path, QString *error)
{
    if (path.trimmed().isEmpty()) return QString();
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("无法读取文件计算哈希：%1").arg(file.errorString());
        return QString();
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) hash.addData(file.read(64 * 1024));
    return QString::fromLatin1(hash.result().toHex());
}

bool AuditLogger::append(const AuditEvent &event, const QString &logPath, QString *error)
{
    if (event.action.trimmed().isEmpty() || event.outcome.trimmed().isEmpty()) {
        if (error) *error = QStringLiteral("审计事件缺少操作或结果");
        return false;
    }
    const QString path = logPath.isEmpty() ? defaultLogPath() : logPath;
    const QFileInfo info(path);
    if (!QDir().mkpath(info.absolutePath())) {
        if (error) *error = QStringLiteral("无法创建审计日志目录");
        return false;
    }
    QString previous;
    if (!verifyInternal(path, nullptr, &previous, error)) return false;

    QString hashError;
    const QString fileHash = fileSha256(event.filePath, &hashError);
    if (!event.filePath.isEmpty() && fileHash.isEmpty()) {
        if (error) *error = hashError;
        return false;
    }
    QJsonObject object;
    object.insert(QStringLiteral("version"), 1);
    object.insert(QStringLiteral("timestamp_utc"),
                  QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
    object.insert(QStringLiteral("actor"), actorName());
    object.insert(QStringLiteral("action"), event.action.left(128));
    object.insert(QStringLiteral("outcome"), event.outcome.left(64));
    object.insert(QStringLiteral("product_id"), event.productId.left(128));
    object.insert(QStringLiteral("subject_id"), event.subjectId.left(256));
    object.insert(QStringLiteral("file_path"), event.filePath.isEmpty()
                  ? QString() : QFileInfo(event.filePath).absoluteFilePath());
    object.insert(QStringLiteral("file_sha256"), fileHash);
    object.insert(QStringLiteral("message"), event.message.left(2048));
    object.insert(QStringLiteral("previous_hash"), previous);
    object.insert(QStringLiteral("record_hash"), recordHash(object));

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        if (error) *error = QStringLiteral("无法写入审计日志：%1").arg(file.errorString());
        return false;
    }
    const QByteArray line = recordBytes(object) + '\n';
    if (file.write(line) != line.size() || !file.flush()) {
        if (error) *error = QStringLiteral("审计日志写入不完整");
        return false;
    }
    return true;
}

bool AuditLogger::verify(const QString &logPath, int *recordCount, QString *error)
{
    if (logPath.trimmed().isEmpty()) {
        if (error) *error = QStringLiteral("请选择审计日志文件");
        return false;
    }
    return verifyInternal(logPath, recordCount, nullptr, error);
}

} // namespace qtlic
