#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QUuid>

#include "batch_issuer.h"
#include "crypto_provider.h"
#include "hardware_fingerprint.h"
#include "key_vault.h"
#include "license_codec.h"

using namespace qtlic;

#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

void printUsage()
{
    QTextStream out(stdout);
    out << "qt-license-cli commands:\n"
        << "  init <vault.qtkv> <product-id>\n"
        << "  collect <product-id> <request.qreq>\n"
        << "  export-runtime <vault.qtkv> <runtime.json> [runtime_config.h]\n"
        << "  issue <vault.qtkv> <request.qreq> <license.qtlic> <mode> [mode-options] [customer-id]\n"
        << "    modes: perpetual, fixed_expiry, validity_duration, runtime_quota, hybrid\n"
        << "    fixed_expiry: <expires-iso>; validity_duration/runtime_quota: <seconds>\n"
        << "    hybrid: <expires-iso> <runtime-seconds>\n"
        << "  batch <vault.qtkv> <batch.csv|json> <output-directory>\n"
        << "  verify <runtime.json> <license.qtlic> [request.qreq]\n"
        << "  inspect <runtime.json> <license.qtlic>\n"
        << "Set QTLIC_PASSWORD for commands that open a vault.\n";
}

bool writeJson(const QString &path, const QJsonObject &object, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly)) {
        if (error) *error = QStringLiteral("输出文件已存在或无法写入");
        return false;
    }
    return file.write(QJsonDocument(object).toJson(QJsonDocument::Indented)) > 0;
}

bool readJson(const QString &path, QJsonObject *object, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 1024 * 1024) {
        if (error) *error = QStringLiteral("无法读取 JSON 文件");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("JSON 格式无效");
        return false;
    }
    *object = document.object();
    return true;
}

QByteArray password(QString *error)
{
    QByteArray value = qEnvironmentVariable("QTLIC_PASSWORD").toUtf8();
    if (!value.isEmpty()) return value;

    QTextStream prompt(stderr);
    prompt << "Vault password: " << flush;
#ifdef Q_OS_WIN
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    const bool hasConsole = input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &oldMode);
    if (hasConsole) SetConsoleMode(input, oldMode & ~ENABLE_ECHO_INPUT);
#else
    termios oldMode;
    const bool hasConsole = tcgetattr(STDIN_FILENO, &oldMode) == 0;
    if (hasConsole) {
        termios hiddenMode = oldMode;
        hiddenMode.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &hiddenMode);
    }
#endif
    value = QTextStream(stdin).readLine().toUtf8();
#ifdef Q_OS_WIN
    if (hasConsole) SetConsoleMode(input, oldMode);
#else
    if (hasConsole) tcsetattr(STDIN_FILENO, TCSANOW, &oldMode);
#endif
    prompt << '\n' << flush;
    if (value.isEmpty() && error) *error = QStringLiteral("密钥库口令为空");
    return value;
}

bool openVault(const QString &path, KeyVaultMaterial *keys, QString *error)
{
    QByteArray pass = password(error);
    const bool opened = !pass.isEmpty() && KeyVault::open(path, pass, keys, error);
    CryptoProvider::wipe(pass);
    return opened;
}

bool loadRuntime(const QString &path, QString *productId, QByteArray *rootPublic,
                 QHash<QString, QByteArray> *keys, QString *error)
{
    QJsonObject object;
    if (!readJson(path, &object, error)
            || object.value(QStringLiteral("format")).toString()
            != QLatin1String("qt-license-runtime-config")
            || object.value(QStringLiteral("version")).toInt(-1) != 1) {
        if (error && error->isEmpty()) *error = QStringLiteral("Runtime 配置无效");
        return false;
    }
    *productId = object.value(QStringLiteral("product_id")).toString();
    if (!LicenseCodec::base64UrlDecode(
                object.value(QStringLiteral("root_public_key")).toString(), rootPublic)) {
        if (error) *error = QStringLiteral("Runtime 根公钥无效");
        return false;
    }
    const QJsonObject keyObject = object.value(QStringLiteral("product_decryption_keys")).toObject();
    for (auto it = keyObject.constBegin(); it != keyObject.constEnd(); ++it) {
        QByteArray key;
        if (!LicenseCodec::base64UrlDecode(it.value().toString(), &key)
                || key.size() != CryptoProvider::AeadKeyBytes) {
            if (error) *error = QStringLiteral("Runtime 产品密钥无效");
            return false;
        }
        keys->insert(it.key(), key);
    }
    return !productId->isEmpty() && rootPublic->size() == 32 && !keys->isEmpty();
}

int fail(const QString &error)
{
    QTextStream(stderr) << error << '\n';
    return 1;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments();
    if (args.size() < 2) {
        printUsage();
        return 2;
    }
    const QString command = args.at(1);
    QString error;

    if (command == QLatin1String("init") && args.size() == 4) {
        KeyVaultMaterial keys;
        QByteArray pass = password(&error);
        const bool created = !pass.isEmpty()
                && KeyVault::create(args.at(2), pass, args.at(3), &keys, &error);
        CryptoProvider::wipe(pass);
        if (!created)
            return fail(error);
        keys.clearSecrets();
        QTextStream(stdout) << "created " << args.at(2) << '\n';
        return 0;
    }

    if (command == QLatin1String("collect") && args.size() == 4) {
        QStringList warnings;
        const QVector<HardwareValue> hardware = HardwareFingerprint::collect(&warnings);
        if (hardware.isEmpty()) return fail(QStringLiteral("没有采集到可用硬件信息"));
        if (!writeJson(args.at(3), HardwareFingerprint::requestToJson(args.at(2), hardware), &error))
            return fail(error);
        for (const QString &warning : warnings) QTextStream(stderr) << warning << '\n';
        QTextStream(stdout) << "collected " << hardware.size() << " hardware values\n";
        return 0;
    }

    if (command == QLatin1String("export-runtime") && (args.size() == 4 || args.size() == 5)) {
        KeyVaultMaterial keys;
        if (!openVault(args.at(2), &keys, &error)
                || !KeyVault::exportRuntimeJson(args.at(3), keys, &error)
                || (args.size() == 5 && !KeyVault::exportRuntimeHeader(args.at(4), keys, &error))) {
            keys.clearSecrets();
            return fail(error);
        }
        keys.clearSecrets();
        QTextStream(stdout) << "runtime config exported\n";
        return 0;
    }

    if (command == QLatin1String("issue") && args.size() >= 6) {
        KeyVaultMaterial keys;
        if (!openVault(args.at(2), &keys, &error)) return fail(error);
        QJsonObject request;
        QString requestProduct;
        QVector<HardwareValue> hardware;
        if (!readJson(args.at(3), &request, &error)
                || !HardwareFingerprint::requestFromJson(
                    request, &requestProduct, &hardware, &error)
                || requestProduct != keys.productId) {
            keys.clearSecrets();
            return fail(error.isEmpty() ? QStringLiteral("硬件请求产品不匹配") : error);
        }
        LicensePayload payload;
        payload.licenseId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        payload.productId = keys.productId;
        payload.issuedAt = QDateTime::currentSecsSinceEpoch();
        if (!licenseModeFromString(args.at(5), &payload.licenseMode)) {
            keys.clearSecrets();
            return fail(QStringLiteral("授权模式无效"));
        }
        int nextArg = 6;
        if (payload.licenseMode == LicenseMode::FixedExpiry
                || payload.licenseMode == LicenseMode::Hybrid) {
            if (args.size() <= nextArg) {
                keys.clearSecrets();
                return fail(QStringLiteral("该模式需要 expires-iso"));
            }
            const QDateTime expiry = QDateTime::fromString(args.at(nextArg++), Qt::ISODate);
            payload.expiresAt = expiry.isValid() ? expiry.toUTC().toSecsSinceEpoch() : -1;
        }
        if (payload.licenseMode == LicenseMode::ValidityDuration
                || payload.licenseMode == LicenseMode::RuntimeQuota
                || payload.licenseMode == LicenseMode::Hybrid) {
            if (args.size() <= nextArg) {
                keys.clearSecrets();
                return fail(QStringLiteral("该模式需要时长秒数"));
            }
            payload.maxRuntimeSeconds = args.at(nextArg++).toLongLong();
        }
        if (args.size() > nextArg) payload.customerId = args.at(nextArg);
        payload.features << QStringLiteral("basic");
        payload.binding = HardwareFingerprint::bindingFromValues(
                    hardware, QStringLiteral("all"), hardware.size(), &error);
        const bool issued = LicenseCodec::issueToFile(payload, keys, args.at(4), &error);
        keys.clearSecrets();
        if (!issued) return fail(error);
        QTextStream(stdout) << payload.licenseId << '\n';
        return 0;
    }

    if (command == QLatin1String("batch") && args.size() == 5) {
        KeyVaultMaterial keys;
        if (!openVault(args.at(2), &keys, &error)) return fail(error);
        BatchIssueResult result;
        const bool issued = BatchIssuer::issueFile(args.at(3), args.at(4), keys, &result, &error);
        keys.clearSecrets();
        if (!issued) return fail(error);
        QTextStream(stdout) << result.batchId << " " << result.issuedCount << '\n';
        return 0;
    }

    if ((command == QLatin1String("verify") || command == QLatin1String("inspect"))
            && args.size() >= 4) {
        QString productId;
        QByteArray rootPublic;
        QHash<QString, QByteArray> decryptionKeys;
        if (!loadRuntime(args.at(2), &productId, &rootPublic, &decryptionKeys, &error))
            return fail(error);
        LicenseDecision decision;
        if (command == QLatin1String("inspect")) {
            decision = LicenseCodec::verifyContainer(args.at(3), productId, rootPublic, decryptionKeys);
        } else {
            VerifyOptions options;
            options.productId = productId;
            options.licensePath = args.at(3);
            options.rootPublicKey = rootPublic;
            options.productDecryptionKeys = decryptionKeys;
            if (args.size() >= 5) {
                QJsonObject request;
                QString requestProduct;
                if (!readJson(args.at(4), &request, &error)
                        || !HardwareFingerprint::requestFromJson(
                            request, &requestProduct, &options.hardware, &error)) return fail(error);
                if (requestProduct != productId) {
                    return fail(QStringLiteral("硬件请求产品与 Runtime 配置不匹配"));
                }
            }
            decision = LicenseCodec::verifyFile(options);
        }
        QJsonObject output;
        if (!decision.payload.licenseId.isEmpty()) {
            output = licensePayloadToJson(decision.payload);
        }
        output.insert(QStringLiteral("status"), licenseStatusToString(decision.status));
        output.insert(QStringLiteral("message"), decision.message);
        QTextStream(stdout) << QJsonDocument(output).toJson(QJsonDocument::Indented);
        return decision.valid() ? 0 : 3;
    }

    printUsage();
    return 2;
}
