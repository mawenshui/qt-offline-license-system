#include "hardware_fingerprint.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QSysInfo>
#include <QUuid>

#include <functional>

namespace qtlic {

namespace {

#ifdef Q_OS_LINUX
QString readTextFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }
    return QString::fromUtf8(file.readAll()).trimmed();
}
#endif

QStringList runCommand(const QString &program, const QStringList &arguments, QStringList *warnings)
{
    QProcess process;
    process.start(program, arguments, QIODevice::ReadOnly);
    if (!process.waitForStarted(3000) || !process.waitForFinished(8000)) {
        process.kill();
        process.waitForFinished(1000);
        if (warnings) warnings->append(QStringLiteral("硬件命令超时: %1").arg(program));
        return QStringList();
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (warnings) warnings->append(QStringLiteral("硬件命令失败: %1").arg(program));
        return QStringList();
    }
    const QString text = QString::fromLocal8Bit(process.readAllStandardOutput());
    QStringList lines = text.split(QRegularExpression(QStringLiteral("[\r\n]+")),
                                   QString::SkipEmptyParts);
    for (QString &line : lines) line = line.trimmed();
    lines.removeAll(QString());
    return lines;
}

void addValue(QVector<HardwareValue> *result, const QString &slot, const QString &type,
              const QString &raw, QStringList *warnings)
{
    QString reason;
    if (!HardwareFingerprint::isUsable(type, raw, &reason)) {
        if (warnings && !raw.trimmed().isEmpty()) {
            warnings->append(QStringLiteral("忽略%1：%2")
                             .arg(HardwareFingerprint::slotDisplayName(slot), reason));
        }
        return;
    }
    const QString normalized = HardwareFingerprint::normalize(type, raw);
    HardwareValue value;
    value.slot = slot;
    value.type = type;
    value.value = normalized;
    value.hash = HardwareFingerprint::hash(type, normalized);
    value.displayHint = normalized.size() <= 4
            ? normalized : QStringLiteral("***") + normalized.right(4);
    result->append(value);
}

QString hardwareClaimKey(const QString &type, const QString &hash)
{
    return type + QChar(0x1f) + hash;
}

int maximumBindingMatches(const HardwareBinding &binding,
                          const QVector<HardwareValue> &actual)
{
    QHash<QString, int> claimIndexes;
    for (const HardwareValue &value : actual) {
        QString hashValue = value.hash;
        if (hashValue.isEmpty() && HardwareFingerprint::isUsable(value.type, value.value)) {
            hashValue = HardwareFingerprint::hash(value.type, value.value);
        }
        if (hashValue.isEmpty()) continue;
        const QString key = hardwareClaimKey(value.type, hashValue);
        if (!claimIndexes.contains(key)) claimIndexes.insert(key, claimIndexes.size());
    }

    QVector<QVector<int>> candidates(binding.bindingSlots.size());
    for (int slotIndex = 0; slotIndex < binding.bindingSlots.size(); ++slotIndex) {
        const BindingSlot &slot = binding.bindingSlots.at(slotIndex);
        for (const QString &expected : slot.acceptedHashes) {
            const int claimIndex = claimIndexes.value(
                        hardwareClaimKey(slot.type, expected), -1);
            if (claimIndex >= 0 && !candidates[slotIndex].contains(claimIndex)) {
                candidates[slotIndex].append(claimIndex);
            }
        }
    }

    QVector<int> claimOwners(claimIndexes.size(), -1);
    std::function<bool(int, QVector<bool> *)> assignSlot;
    assignSlot = [&candidates, &claimOwners, &assignSlot](int slotIndex,
                                                          QVector<bool> *visited) {
        for (int claimIndex : candidates.at(slotIndex)) {
            if (visited->at(claimIndex)) continue;
            (*visited)[claimIndex] = true;
            if (claimOwners.at(claimIndex) < 0
                    || assignSlot(claimOwners.at(claimIndex), visited)) {
                claimOwners[claimIndex] = slotIndex;
                return true;
            }
        }
        return false;
    };

    int matched = 0;
    for (int slotIndex = 0; slotIndex < candidates.size(); ++slotIndex) {
        QVector<bool> visited(claimOwners.size(), false);
        if (assignSlot(slotIndex, &visited)) ++matched;
    }
    return matched;
}

#ifdef Q_OS_WIN
QStringList powershell(const QString &command, QStringList *warnings)
{
    return runCommand(QStringLiteral("powershell.exe"),
                      QStringList() << QStringLiteral("-NoProfile")
                                    << QStringLiteral("-NonInteractive")
                                    << QStringLiteral("-Command") << command,
                      warnings);
}
#endif

} // namespace

QString HardwareFingerprint::slotDisplayName(const QString &slot)
{
    if (slot == QLatin1String("machine-id")) return QStringLiteral("系统机器标识");
    if (slot == QLatin1String("system-uuid")) return QStringLiteral("系统 UUID");
    if (slot == QLatin1String("cpu")) return QStringLiteral("处理器");
    if (slot == QLatin1String("board")) return QStringLiteral("主板");
    if (slot == QLatin1String("disk")) return QStringLiteral("硬盘");

    const QRegularExpressionMatch disk = QRegularExpression(
                QStringLiteral("^disk-(\\d+)$")).match(slot);
    if (disk.hasMatch()) {
        return QStringLiteral("硬盘 %1").arg(disk.captured(1).toInt() + 1);
    }
    const QRegularExpressionMatch custom = QRegularExpression(
                QStringLiteral("^custom-(\\d+)$")).match(slot);
    if (custom.hasMatch()) {
        return QStringLiteral("自定义硬件 %1").arg(custom.captured(1));
    }
    return slot;
}

QString HardwareFingerprint::typeDisplayName(const QString &type)
{
    if (type == QLatin1String("machine_id")) return QStringLiteral("系统机器标识");
    if (type == QLatin1String("system_uuid")) return QStringLiteral("系统 UUID");
    if (type == QLatin1String("cpu")) return QStringLiteral("处理器");
    if (type == QLatin1String("board")) return QStringLiteral("主板");
    if (type == QLatin1String("disk")) return QStringLiteral("硬盘");
    if (type == QLatin1String("mac")) return QStringLiteral("网卡");
    return type;
}

QString HardwareFingerprint::normalize(const QString &type, const QString &value)
{
    QString normalized = value.normalized(QString::NormalizationForm_KC);
    normalized.remove(QChar::Null);
    normalized = normalized.trimmed().toUpper();
    normalized.replace(QRegularExpression(QStringLiteral("\\s+")), QStringLiteral(" "));

    if (type == QLatin1String("system_uuid")) {
        const QUuid uuid(normalized);
        if (!uuid.isNull()) {
            normalized = uuid.toString(QUuid::WithoutBraces).toUpper();
        }
    }
    return normalized;
}

bool HardwareFingerprint::isUsable(const QString &type, const QString &value, QString *reason)
{
    const QString normalized = normalize(type, value);
    static const QSet<QString> rejected = {
        QStringLiteral("UNKNOWN"), QStringLiteral("NONE"),
        QStringLiteral("DEFAULT STRING"),
        QStringLiteral("TO BE FILLED BY O.E.M."),
        QStringLiteral("00000000-0000-0000-0000-000000000000"),
        QStringLiteral("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
    };
    if (normalized.isEmpty() || normalized.size() < 4 || rejected.contains(normalized)) {
        if (reason) *reason = QStringLiteral("硬件值为空、过短或为占位值");
        return false;
    }
    if (QRegularExpression(QStringLiteral("^[0F\\- ]+$")).match(normalized).hasMatch()) {
        if (reason) *reason = QStringLiteral("硬件值为全零或全 F");
        return false;
    }
    return true;
}

QString HardwareFingerprint::hash(const QString &type, const QString &value)
{
    const QByteArray normalized = normalize(type, value).toUtf8();
    QByteArray input("QTLIC-HW-V1", 11);
    input.append('\0');
    input.append(type.toUtf8());
    input.append('\0');
    input.append(normalized);
    return QStringLiteral("sha256:")
            + QString::fromLatin1(QCryptographicHash::hash(input, QCryptographicHash::Sha256).toHex());
}

QVector<HardwareValue> HardwareFingerprint::collect(QStringList *warnings)
{
    QVector<HardwareValue> result;
    const QByteArray machineId = QSysInfo::machineUniqueId();
    if (!machineId.isEmpty()) {
        addValue(&result, QStringLiteral("machine-id"), QStringLiteral("machine_id"),
                 QString::fromLatin1(machineId), warnings);
    }

#ifdef Q_OS_WIN
    const QStringList cpu = powershell(
                QStringLiteral("Get-CimInstance Win32_Processor | ForEach-Object {$_.ProcessorId}"),
                warnings);
    if (!cpu.isEmpty()) addValue(&result, QStringLiteral("cpu"), QStringLiteral("cpu"), cpu.first(), warnings);

    const QStringList board = powershell(
                QStringLiteral("Get-CimInstance Win32_BaseBoard | ForEach-Object {$_.SerialNumber}"),
                warnings);
    if (!board.isEmpty()) addValue(&result, QStringLiteral("board"), QStringLiteral("board"), board.first(), warnings);

    const QStringList uuid = powershell(
                QStringLiteral("Get-CimInstance Win32_ComputerSystemProduct | ForEach-Object {$_.UUID}"),
                warnings);
    if (!uuid.isEmpty()) addValue(&result, QStringLiteral("system-uuid"),
                                  QStringLiteral("system_uuid"), uuid.first(), warnings);

    const QStringList disks = powershell(
                QStringLiteral("Get-CimInstance Win32_DiskDrive | ForEach-Object {$_.SerialNumber}"),
                warnings);
    for (int i = 0; i < disks.size(); ++i) {
        addValue(&result, QStringLiteral("disk-%1").arg(i), QStringLiteral("disk"), disks.at(i), warnings);
    }
#elif defined(Q_OS_LINUX)
    addValue(&result, QStringLiteral("board"), QStringLiteral("board"),
             readTextFile(QStringLiteral("/sys/devices/virtual/dmi/id/board_serial")), warnings);
    addValue(&result, QStringLiteral("system-uuid"), QStringLiteral("system_uuid"),
             readTextFile(QStringLiteral("/sys/devices/virtual/dmi/id/product_uuid")), warnings);

    const QDir blocks(QStringLiteral("/sys/class/block"));
    const QStringList entries = blocks.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    int diskIndex = 0;
    for (const QString &entry : entries) {
        if (entry.startsWith(QLatin1String("loop")) || entry.startsWith(QLatin1String("ram"))) continue;
        const QString serial = readTextFile(blocks.filePath(entry + QStringLiteral("/device/serial")));
        if (!serial.isEmpty()) {
            addValue(&result, QStringLiteral("disk-%1").arg(diskIndex++),
                     QStringLiteral("disk"), serial, warnings);
        }
    }

    QFile cpuInfo(QStringLiteral("/proc/cpuinfo"));
    if (cpuInfo.open(QIODevice::ReadOnly)) {
        const QString text = QString::fromUtf8(cpuInfo.readAll());
        const QRegularExpressionMatch match = QRegularExpression(
                    QStringLiteral("(?im)^Serial\\s*:\\s*(.+)$")).match(text);
        if (match.hasMatch()) {
            addValue(&result, QStringLiteral("cpu"), QStringLiteral("cpu"),
                     match.captured(1), warnings);
        }
    }
#endif
    return result;
}

HardwareBinding HardwareFingerprint::bindingFromValues(const QVector<HardwareValue> &values,
                                                        const QString &mode, int minimum,
                                                        QString *error)
{
    HardwareBinding binding;
    binding.mode = mode;
    for (const HardwareValue &value : values) {
        QString hashValue = value.hash;
        if (hashValue.isEmpty() && isUsable(value.type, value.value)) {
            hashValue = hash(value.type, value.value);
        }
        if (value.slot.isEmpty() || value.type.isEmpty() || hashValue.isEmpty()) continue;

        int index = -1;
        for (int i = 0; i < binding.bindingSlots.size(); ++i) {
            if (binding.bindingSlots.at(i).slot == value.slot) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            BindingSlot slot;
            slot.slot = value.slot;
            slot.type = value.type;
            slot.acceptedHashes.append(hashValue);
            binding.bindingSlots.append(slot);
        } else if (binding.bindingSlots[index].type == value.type
                   && !binding.bindingSlots[index].acceptedHashes.contains(hashValue)) {
            binding.bindingSlots[index].acceptedHashes.append(hashValue);
        }
    }

    if (binding.bindingSlots.isEmpty()) {
        if (error) *error = QStringLiteral("至少需要一个有效硬件绑定值");
        return HardwareBinding();
    }
    if (mode == QLatin1String("all")) binding.minimum = binding.bindingSlots.size();
    else if (mode == QLatin1String("any")) binding.minimum = 1;
    else binding.minimum = minimum;

    if (binding.mode != QLatin1String("all") && binding.mode != QLatin1String("any")
            && binding.mode != QLatin1String("threshold")) {
        if (error) *error = QStringLiteral("硬件匹配模式无效");
        return HardwareBinding();
    }
    if (binding.minimum < 1 || binding.minimum > binding.bindingSlots.size()) {
        if (error) *error = QStringLiteral("硬件匹配阈值无效");
        return HardwareBinding();
    }
    return binding;
}

bool HardwareFingerprint::matches(const HardwareBinding &binding,
                                  const QVector<HardwareValue> &actual, int *matchedSlots)
{
    const int matched = maximumBindingMatches(binding, actual);
    if (matchedSlots) *matchedSlots = matched;
    return matched >= binding.minimum;
}

QJsonObject HardwareFingerprint::requestToJson(const QString &productId,
                                               const QVector<HardwareValue> &values)
{
    QJsonArray hardware;
    for (const HardwareValue &value : values) {
        QJsonObject item;
        item.insert(QStringLiteral("slot"), value.slot);
        item.insert(QStringLiteral("type"), value.type);
        item.insert(QStringLiteral("hash"), value.hash.isEmpty()
                    ? hash(value.type, value.value) : value.hash);
        item.insert(QStringLiteral("display_hint"), value.displayHint);
        hardware.append(item);
    }
    QJsonObject host;
    host.insert(QStringLiteral("os"), QSysInfo::productType());
    host.insert(QStringLiteral("arch"), QSysInfo::currentCpuArchitecture());

    QJsonObject object;
    object.insert(QStringLiteral("format"), QStringLiteral("qt-license-request"));
    object.insert(QStringLiteral("version"), 1);
    object.insert(QStringLiteral("request_id"), QUuid::createUuid().toString(QUuid::WithoutBraces));
    object.insert(QStringLiteral("created_at"), static_cast<double>(QDateTime::currentSecsSinceEpoch()));
    object.insert(QStringLiteral("product_id"), productId);
    object.insert(QStringLiteral("fingerprint_version"), 1);
    object.insert(QStringLiteral("host"), host);
    object.insert(QStringLiteral("hardware"), hardware);
    return object;
}

bool HardwareFingerprint::requestFromJson(const QJsonObject &object, QString *productId,
                                          QVector<HardwareValue> *values, QString *error)
{
    if (!productId || !values) {
        if (error) *error = QStringLiteral("请求输出参数无效");
        return false;
    }
    if (object.value(QStringLiteral("format")).toString()
            != QLatin1String("qt-license-request")
            || object.value(QStringLiteral("version")).toInt(-1) != 1
            || object.value(QStringLiteral("fingerprint_version")).toInt(-1) != 1) {
        if (error) *error = QStringLiteral("硬件请求格式或版本无效");
        return false;
    }
    const QString requestProduct = object.value(QStringLiteral("product_id")).toString();
    if (requestProduct.isEmpty()) {
        if (error) *error = QStringLiteral("硬件请求缺少产品标识（product_id）");
        return false;
    }

    QVector<HardwareValue> result;
    const QJsonArray hardware = object.value(QStringLiteral("hardware")).toArray();
    for (const QJsonValue &entry : hardware) {
        const QJsonObject item = entry.toObject();
        HardwareValue value;
        value.slot = item.value(QStringLiteral("slot")).toString();
        value.type = item.value(QStringLiteral("type")).toString();
        value.hash = item.value(QStringLiteral("hash")).toString();
        value.displayHint = item.value(QStringLiteral("display_hint")).toString();
        if (value.slot.isEmpty() || value.type.isEmpty()
                || !QRegularExpression(QStringLiteral("^sha256:[0-9a-f]{64}$"))
                .match(value.hash).hasMatch()) {
            if (error) *error = QStringLiteral("硬件请求包含无效条目");
            return false;
        }
        result.append(value);
    }
    if (result.isEmpty()) {
        if (error) *error = QStringLiteral("硬件请求没有可用硬件信息");
        return false;
    }
    *productId = requestProduct;
    *values = result;
    return true;
}

} // namespace qtlic
