#include "batch_issuer.h"

#include "crypto_provider.h"
#include "hardware_fingerprint.h"
#include "license_codec.h"

#include <QDateTime>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QUuid>

namespace qtlic {

namespace {

struct BatchRecord {
    QString rowId;
    QString customerId;
    QString customerName;
    QString orderId;
    QString productId;
    LicenseMode mode = LicenseMode::Perpetual;
    qint64 expiresAt = -1;
    qint64 maxRuntimeSeconds = -1;
    QString bindingMode = QStringLiteral("all");
    int minimum = 1;
    QStringList features;
    QVector<HardwareValue> hardware;
    QString outputName;
};

struct ManifestFile {
    QString path;
    QString licenseId;
    QByteArray sha256;
};

QStringList parseCsvLine(const QString &line, bool *ok)
{
    QStringList fields;
    QString current;
    bool quoted = false;
    for (int i = 0; i < line.size(); ++i) {
        const QChar ch = line.at(i);
        if (quoted) {
            if (ch == QLatin1Char('"')) {
                if (i + 1 < line.size() && line.at(i + 1) == QLatin1Char('"')) {
                    current.append(QLatin1Char('"'));
                    ++i;
                } else {
                    quoted = false;
                }
            } else {
                current.append(ch);
            }
        } else if (ch == QLatin1Char('"') && current.isEmpty()) {
            quoted = true;
        } else if (ch == QLatin1Char(',')) {
            fields.append(current);
            current.clear();
        } else {
            current.append(ch);
        }
    }
    if (quoted) {
        if (ok) *ok = false;
        return QStringList();
    }
    fields.append(current);
    if (ok) *ok = true;
    return fields;
}

qint64 parseIsoUtc(const QString &text)
{
    if (text.trimmed().isEmpty()) return -1;
    QDateTime dateTime = QDateTime::fromString(text.trimmed(), Qt::ISODate);
    if (!dateTime.isValid() || dateTime.timeSpec() == Qt::LocalTime) return -2;
    return dateTime.toUTC().toSecsSinceEpoch();
}

void addRawHardware(QVector<HardwareValue> *hardware, const QString &slot,
                    const QString &type, const QString &value)
{
    if (value.trimmed().isEmpty()) return;
    HardwareValue item;
    item.slot = slot;
    item.type = type;
    item.value = value;
    item.hash = HardwareFingerprint::hash(type, value);
    hardware->append(item);
}

bool parseCsv(const QByteArray &bytes, QVector<BatchRecord> *records, QString *error)
{
    QString text = QString::fromUtf8(bytes);
    if (!text.isEmpty() && text.at(0) == QChar(0xfeff)) text.remove(0, 1);
    const QStringList lines = text.split(QRegularExpression(QStringLiteral("\r?\n")),
                                         QString::SkipEmptyParts);
    if (lines.size() < 2) {
        if (error) *error = QStringLiteral("CSV 没有数据行");
        return false;
    }
    bool ok = false;
    const QStringList headers = parseCsvLine(lines.first(), &ok);
    if (!ok) {
        if (error) *error = QStringLiteral("CSV 表头引号无效");
        return false;
    }
    QHash<QString, int> index;
    for (int i = 0; i < headers.size(); ++i) index.insert(headers.at(i).trimmed(), i);
    auto value = [&index](const QStringList &fields, const QString &name) {
        const int column = index.value(name, -1);
        return column >= 0 && column < fields.size() ? fields.at(column).trimmed() : QString();
    };

    for (int lineNumber = 1; lineNumber < lines.size(); ++lineNumber) {
        const QStringList fields = parseCsvLine(lines.at(lineNumber), &ok);
        if (!ok) {
            if (error) *error = QStringLiteral("CSV 第 %1 行引号无效").arg(lineNumber + 1);
            return false;
        }
        BatchRecord record;
        record.rowId = value(fields, QStringLiteral("row_id"));
        record.customerId = value(fields, QStringLiteral("customer_id"));
        record.customerName = value(fields, QStringLiteral("customer_name"));
        record.orderId = value(fields, QStringLiteral("order_id"));
        record.productId = value(fields, QStringLiteral("product_id"));
        const QString modeText = value(fields, QStringLiteral("license_mode"));
        if (!licenseModeFromString(modeText.isEmpty() ? QStringLiteral("perpetual") : modeText,
                                   &record.mode)) {
            if (error) *error = QStringLiteral("CSV 第 %1 行授权模式无效").arg(lineNumber + 1);
            return false;
        }
        record.expiresAt = parseIsoUtc(value(fields, QStringLiteral("expires_at")));
        bool runtimeOk = false;
        record.maxRuntimeSeconds = value(fields, QStringLiteral("max_runtime_seconds"))
                .toLongLong(&runtimeOk);
        if (!runtimeOk) record.maxRuntimeSeconds = -1;
        record.bindingMode = value(fields, QStringLiteral("binding_mode"));
        if (record.bindingMode.isEmpty()) record.bindingMode = QStringLiteral("all");
        record.minimum = value(fields, QStringLiteral("minimum")).toInt();
        record.features = value(fields, QStringLiteral("features"))
                .split(QLatin1Char('|'), QString::SkipEmptyParts);
        record.outputName = value(fields, QStringLiteral("output_name"));
        addRawHardware(&record.hardware, QStringLiteral("cpu"), QStringLiteral("cpu"),
                       value(fields, QStringLiteral("cpu")));
        addRawHardware(&record.hardware, QStringLiteral("board"), QStringLiteral("board"),
                       value(fields, QStringLiteral("board")));
        addRawHardware(&record.hardware, QStringLiteral("system-uuid"),
                       QStringLiteral("system_uuid"), value(fields, QStringLiteral("system_uuid")));
        addRawHardware(&record.hardware, QStringLiteral("system-disk"), QStringLiteral("disk"),
                       value(fields, QStringLiteral("disk")));
        records->append(record);
    }
    return true;
}

bool parseJson(const QByteArray &bytes, QVector<BatchRecord> *records, QString *error)
{
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("批量 JSON 无效");
        return false;
    }
    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("schema")).toString() != QLatin1String("qt-license-batch")
            || root.value(QStringLiteral("version")).toInt(-1) != 1) {
        if (error) *error = QStringLiteral("批量 JSON schema 或版本无效");
        return false;
    }
    const QJsonObject defaults = root.value(QStringLiteral("defaults")).toObject();
    const QJsonArray inputRecords = root.value(QStringLiteral("records")).toArray();
    for (const QJsonValue &entry : inputRecords) {
        if (!entry.isObject()) {
            if (error) *error = QStringLiteral("批量记录不是对象");
            return false;
        }
        const QJsonObject item = entry.toObject();
        auto stringValue = [&item, &defaults](const QString &key) {
            return item.contains(key) ? item.value(key).toString() : defaults.value(key).toString();
        };
        BatchRecord record;
        record.rowId = item.value(QStringLiteral("row_id")).toString();
        record.customerId = item.value(QStringLiteral("customer_id")).toString();
        record.customerName = item.value(QStringLiteral("customer_name")).toString();
        record.orderId = item.value(QStringLiteral("order_id")).toString();
        record.productId = stringValue(QStringLiteral("product_id"));
        if (!licenseModeFromString(stringValue(QStringLiteral("license_mode")), &record.mode)) {
            if (error) *error = QStringLiteral("JSON 记录授权模式无效");
            return false;
        }
        record.expiresAt = parseIsoUtc(stringValue(QStringLiteral("expires_at")));
        const QJsonValue runtime = item.contains(QStringLiteral("max_runtime_seconds"))
                ? item.value(QStringLiteral("max_runtime_seconds"))
                : defaults.value(QStringLiteral("max_runtime_seconds"));
        record.maxRuntimeSeconds = runtime.isDouble()
                ? static_cast<qint64>(runtime.toDouble()) : -1;
        record.bindingMode = stringValue(QStringLiteral("binding_mode"));
        if (record.bindingMode.isEmpty()) record.bindingMode = QStringLiteral("all");
        record.minimum = item.contains(QStringLiteral("minimum"))
                ? item.value(QStringLiteral("minimum")).toInt(1)
                : defaults.value(QStringLiteral("minimum")).toInt(1);
        const QJsonArray featureValues = item.contains(QStringLiteral("features"))
                ? item.value(QStringLiteral("features")).toArray()
                : defaults.value(QStringLiteral("features")).toArray();
        for (const QJsonValue &feature : featureValues) record.features.append(feature.toString());
        record.outputName = item.value(QStringLiteral("output_name")).toString();

        const QJsonArray hardware = item.value(QStringLiteral("hardware")).toArray();
        for (const QJsonValue &hardwareEntry : hardware) {
            const QJsonObject hw = hardwareEntry.toObject();
            const QString slot = hw.value(QStringLiteral("slot")).toString();
            const QString type = hw.value(QStringLiteral("type")).toString();
            const QJsonArray values = hw.value(QStringLiteral("values")).toArray();
            const QJsonArray hashes = hw.value(QStringLiteral("hashes")).toArray();
            if (!values.isEmpty() && !hashes.isEmpty()) {
                if (error) *error = QStringLiteral("同一硬件槽位不能混用 values 和 hashes");
                return false;
            }
            for (const QJsonValue &raw : values) addRawHardware(&record.hardware, slot, type, raw.toString());
            for (const QJsonValue &hash : hashes) {
                HardwareValue value;
                value.slot = slot;
                value.type = type;
                value.hash = hash.toString();
                record.hardware.append(value);
            }
        }
        records->append(record);
    }
    return !records->isEmpty();
}

bool safeOutputName(const QString &name)
{
    const QString stem = QFileInfo(name).completeBaseName().toUpper();
    static const QRegularExpression reserved(
                QStringLiteral("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$"));
    return !name.isEmpty() && name.size() <= 128
            && QRegularExpression(QStringLiteral("^[A-Za-z0-9._-]+\\.qtlic$"))
            .match(name).hasMatch()
            && !name.contains(QLatin1String(".."))
            && !reserved.match(stem).hasMatch();
}

LicensePayload toPayload(const BatchRecord &record, const KeyVaultMaterial &keys,
                         qint64 issuedAt, QString *error)
{
    LicensePayload payload;
    payload.licenseId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    payload.productId = record.productId.isEmpty() ? keys.productId : record.productId;
    payload.customerId = record.customerId;
    payload.customerName = record.customerName;
    payload.orderId = record.orderId;
    payload.issuedAt = issuedAt;
    payload.licenseMode = record.mode;
    payload.expiresAt = record.expiresAt;
    payload.maxRuntimeSeconds = record.maxRuntimeSeconds;
    payload.features = record.features;
    payload.features.removeDuplicates();
    payload.features.sort();
    payload.issuer = QStringLiteral("QtLicenseIssuer");
    payload.binding = HardwareFingerprint::bindingFromValues(
                record.hardware, record.bindingMode, record.minimum, error);
    return payload;
}

QString csvField(QString value)
{
    if (!value.isEmpty() && QStringLiteral("=+-@").contains(value.at(0))) {
        value.prepend(QLatin1Char('\''));
    }
    value.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + value + QLatin1Char('"');
}

bool writeReport(const QString &path, const QVector<BatchRecord> &records,
                 const QVector<LicensePayload> &payloads, const QStringList &names,
                 QByteArray *sha256, QString *error)
{
    QByteArray bytes("row_id,customer_id,order_id,license_id,file,status,error\r\n");
    for (int i = 0; i < payloads.size(); ++i) {
        const QStringList fields = QStringList()
                << records.at(i).rowId << records.at(i).customerId << records.at(i).orderId
                << payloads.at(i).licenseId << (QStringLiteral("licenses/") + names.at(i))
                << QStringLiteral("issued") << QString();
        QStringList escaped;
        for (const QString &field : fields) escaped.append(csvField(field));
        bytes.append(escaped.join(QLatin1Char(',')).toUtf8());
        bytes.append("\r\n");
    }
    QSaveFile output(path);
    if (!output.open(QIODevice::WriteOnly) || output.write(bytes) != bytes.size()
            || !output.commit()) {
        if (error) *error = QStringLiteral("批次报告写入失败");
        return false;
    }
    if (sha256) *sha256 = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
    return true;
}

bool writeManifest(const QString &path, const QString &batchId, const QString &keyId,
                   const QString &encryptionKeyId, const QByteArray &inputSha256,
                   const QByteArray &reportSha256, const QVector<ManifestFile> &files,
                   const QByteArray &signingSecret, QString *error)
{
    QJsonArray entries;
    for (const ManifestFile &file : files) {
        QJsonObject item;
        item.insert(QStringLiteral("file"), file.path);
        item.insert(QStringLiteral("license_id"), file.licenseId);
        item.insert(QStringLiteral("sha256"), QStringLiteral("sha256:")
                    + QString::fromLatin1(file.sha256.toHex()));
        entries.append(item);
    }
    QJsonObject body;
    body.insert(QStringLiteral("format"), QStringLiteral("qt-license-batch-manifest"));
    body.insert(QStringLiteral("version"), 1);
    body.insert(QStringLiteral("batch_id"), batchId);
    body.insert(QStringLiteral("created_at"), static_cast<double>(QDateTime::currentSecsSinceEpoch()));
    body.insert(QStringLiteral("kid"), keyId);
    body.insert(QStringLiteral("ekid"), encryptionKeyId);
    body.insert(QStringLiteral("input_sha256"), QStringLiteral("sha256:")
                + QString::fromLatin1(inputSha256.toHex()));
    body.insert(QStringLiteral("report_sha256"), QStringLiteral("sha256:")
                + QString::fromLatin1(reportSha256.toHex()));
    body.insert(QStringLiteral("success_count"), files.size());
    body.insert(QStringLiteral("skipped_count"), 0);
    body.insert(QStringLiteral("failed_count"), 0);
    body.insert(QStringLiteral("files"), entries);
    const QByteArray bodyBytes = QJsonDocument(body).toJson(QJsonDocument::Compact);
    QByteArray transcript("QTLIC-BATCH-MANIFEST-V1", 23);
    transcript.append('\0');
    transcript.append(bodyBytes);
    const QByteArray signature = CryptoProvider::sign(transcript, signingSecret, error);
    if (signature.isEmpty()) return false;
    QJsonObject envelope;
    envelope.insert(QStringLiteral("body"),
                    QString::fromLatin1(LicenseCodec::base64UrlEncode(bodyBytes)));
    envelope.insert(QStringLiteral("signature"),
                    QString::fromLatin1(LicenseCodec::base64UrlEncode(signature)));
    QSaveFile output(path);
    const QByteArray bytes = QJsonDocument(envelope).toJson(QJsonDocument::Indented);
    if (!output.open(QIODevice::WriteOnly) || output.write(bytes) != bytes.size()
            || !output.commit()) {
        if (error) *error = QStringLiteral("批次 manifest 写入失败");
        return false;
    }
    return true;
}

} // namespace

bool BatchIssuer::issueFile(const QString &inputPath, const QString &outputDirectory,
                            const KeyVaultMaterial &keys, BatchIssueResult *result,
                            QString *error)
{
    if (!keys.isComplete() || !result) {
        if (error) *error = QStringLiteral("密钥库或输出参数无效");
        return false;
    }
    QFile input(inputPath);
    if (!input.open(QIODevice::ReadOnly) || input.size() <= 0 || input.size() > 32 * 1024 * 1024) {
        if (error) *error = QStringLiteral("无法读取批量输入或文件过大");
        return false;
    }
    const QByteArray inputBytes = input.readAll();
    QVector<BatchRecord> records;
    const bool parsed = inputPath.endsWith(QLatin1String(".csv"), Qt::CaseInsensitive)
            ? parseCsv(inputBytes, &records, error)
            : parseJson(inputBytes, &records, error);
    if (!parsed || records.isEmpty()) return false;

    const QFileInfo outputInfo(outputDirectory);
    if (outputInfo.exists()) {
        if (error) *error = QStringLiteral("批次输出目录已存在，拒绝覆盖");
        return false;
    }
    const QString outputName = outputInfo.fileName();
    QDir parent = outputInfo.dir();
    if (!parent.exists() && !QDir().mkpath(parent.absolutePath())) {
        if (error) *error = QStringLiteral("无法创建批次父目录");
        return false;
    }
    const QString batchId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString tempPath = parent.filePath(QStringLiteral(".") + outputName
                                             + QStringLiteral(".tmp-") + batchId);
    QDir tempDir;
    if (!tempDir.mkpath(QDir(tempPath).filePath(QStringLiteral("licenses")))) {
        if (error) *error = QStringLiteral("无法创建临时批次目录");
        return false;
    }

    QVector<LicensePayload> payloads;
    QStringList names;
    QSet<QString> usedNames;
    const qint64 issuedAt = QDateTime::currentSecsSinceEpoch();
    for (int i = 0; i < records.size(); ++i) {
        BatchRecord record = records.at(i);
        if (record.productId.isEmpty()) record.productId = keys.productId;
        if (record.productId != keys.productId) {
            if (error) *error = QStringLiteral("第 %1 行产品与密钥库不匹配").arg(i + 1);
            QDir(tempPath).removeRecursively();
            return false;
        }
        QString name = record.outputName;
        if (name.isEmpty()) name = QStringLiteral("%1-%2.qtlic")
                .arg(record.customerId.isEmpty() ? QStringLiteral("license") : record.customerId,
                     QString::number(i + 1));
        const QString portableName = name.toCaseFolded();
        if (!safeOutputName(name) || usedNames.contains(portableName)) {
            if (error) *error = QStringLiteral("第 %1 行输出名无效或重复: %2").arg(i + 1).arg(name);
            QDir(tempPath).removeRecursively();
            return false;
        }
        usedNames.insert(portableName);
        QString payloadError;
        LicensePayload payload = toPayload(record, keys, issuedAt, &payloadError);
        if (!validateLicensePayload(payload, &payloadError)) {
            if (error) *error = QStringLiteral("第 %1 行预检失败: %2").arg(i + 1).arg(payloadError);
            QDir(tempPath).removeRecursively();
            return false;
        }
        payloads.append(payload);
        names.append(name);
    }

    QVector<ManifestFile> manifestFiles;
    for (int i = 0; i < payloads.size(); ++i) {
        const QString relative = QStringLiteral("licenses/") + names.at(i);
        const QString path = QDir(tempPath).filePath(relative);
        QString issueError;
        if (!LicenseCodec::issueToFile(payloads.at(i), keys, path, &issueError)) {
            if (error) *error = QStringLiteral("第 %1 个授权生成失败: %2").arg(i + 1).arg(issueError);
            QDir(tempPath).removeRecursively();
            return false;
        }
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            if (error) *error = QStringLiteral("无法读取生成结果进行 manifest 哈希");
            QDir(tempPath).removeRecursively();
            return false;
        }
        ManifestFile manifestFile;
        manifestFile.path = relative;
        manifestFile.licenseId = payloads.at(i).licenseId;
        manifestFile.sha256 = QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256);
        manifestFiles.append(manifestFile);
    }
    QByteArray reportSha256;
    if (!writeReport(QDir(tempPath).filePath(QStringLiteral("batch-report.csv")),
                     records, payloads, names, &reportSha256, error)) {
        QDir(tempPath).removeRecursively();
        return false;
    }
    if (!writeManifest(QDir(tempPath).filePath(QStringLiteral("batch-manifest.json")),
                       batchId, keys.keyId, keys.encryptionKeyId,
                       QCryptographicHash::hash(inputBytes, QCryptographicHash::Sha256),
                       reportSha256, manifestFiles, keys.signingSecretKey, error)) {
        QDir(tempPath).removeRecursively();
        return false;
    }
    if (!parent.rename(QFileInfo(tempPath).fileName(), outputName)) {
        if (error) *error = QStringLiteral("批次原子发布失败");
        QDir(tempPath).removeRecursively();
        return false;
    }
    result->batchId = batchId;
    result->issuedCount = payloads.size();
    result->outputDirectory = outputInfo.absoluteFilePath();
    return true;
}

} // namespace qtlic
