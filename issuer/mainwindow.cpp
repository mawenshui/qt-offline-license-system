#include "mainwindow.h"

#include "batch_issuer.h"
#include "crypto_provider.h"
#include "hardware_fingerprint.h"
#include "key_vault.h"
#include "license_codec.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

using namespace qtlic;

namespace {

constexpr int TechnicalValueRole = Qt::UserRole;
constexpr int FriendlyTextRole = Qt::UserRole + 1;

QWidget *pathRow(QLineEdit *edit, const QString &buttonText, QObject *receiver,
                  const char *slot)
{
    QWidget *widget = new QWidget;
    QHBoxLayout *layout = new QHBoxLayout(widget);
    layout->setContentsMargins(0, 0, 0, 0);
    QPushButton *button = new QPushButton(buttonText);
    layout->addWidget(edit, 1);
    layout->addWidget(button);
    QObject::connect(button, SIGNAL(clicked()), receiver, slot);
    return widget;
}

QTableWidgetItem *hardwareKeyItem(const QString &friendlyText,
                                  const QString &technicalValue)
{
    QTableWidgetItem *item = new QTableWidgetItem(friendlyText);
    item->setData(TechnicalValueRole, technicalValue);
    item->setData(FriendlyTextRole, friendlyText);
    item->setToolTip(QStringLiteral(
        "专业字段名：%1\n如需高级编辑，请输入专业字段名。")
                     .arg(technicalValue));
    return item;
}

QString hardwareTechnicalValue(const QTableWidgetItem *item)
{
    if (!item) return QString();
    const QString text = item->text().trimmed();
    if (text == item->data(FriendlyTextRole).toString()) {
        return item->data(TechnicalValueRole).toString();
    }
    return text;
}

QString rawPayloadText(const LicenseDecision &decision, bool fullLocalCheck)
{
    QJsonObject object;
    if (!decision.payload.licenseId.isEmpty()) {
        object = licensePayloadToJson(decision.payload);
    }
    object.insert(QStringLiteral("status"), licenseStatusToString(decision.status));
    object.insert(QStringLiteral("message"), decision.message);
    object.insert(QStringLiteral("signing_key_id"), decision.signingKeyId);
    object.insert(QStringLiteral("encryption_key_id"), decision.encryptionKeyId);
    object.insert(QStringLiteral("validation_scope"), fullLocalCheck
                  ? QStringLiteral("full_local") : QStringLiteral("container_only"));
    if (decision.effectiveUtc > 0) {
        object.insert(QStringLiteral("effective_utc"),
                      static_cast<double>(decision.effectiveUtc));
    }
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented));
}

QString displayText(const QString &text)
{
    return text.trimmed().isEmpty() ? QStringLiteral("未填写") : text.trimmed();
}

QString utcOffsetText(int offsetSeconds)
{
    const QChar sign = offsetSeconds < 0 ? QLatin1Char('-') : QLatin1Char('+');
    const int absolute = qAbs(offsetSeconds);
    const int hours = absolute / 3600;
    const int minutes = (absolute % 3600) / 60;
    return QStringLiteral("%1%2:%3").arg(sign).arg(hours, 2, 10, QLatin1Char('0'))
            .arg(minutes, 2, 10, QLatin1Char('0'));
}

QString localZoneText(const QDateTime &dateTime)
{
    const QDateTime local = dateTime.toLocalTime();
    return QStringLiteral("%1 / UTC%2")
            .arg(local.timeZoneAbbreviation(), utcOffsetText(local.offsetFromUtc()));
}

QString formatTimestamp(qint64 seconds)
{
    if (seconds < 0) return QStringLiteral("未设置");
    const QDateTime utc = QDateTime::fromSecsSinceEpoch(seconds, Qt::UTC);
    const QDateTime local = utc.toLocalTime();
    return QStringLiteral("%1 %2（UTC%3；对应 %4 UTC）")
            .arg(local.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
                 local.timeZoneAbbreviation(), utcOffsetText(local.offsetFromUtc()),
                 utc.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
}

QString formatDuration(qint64 seconds)
{
    if (seconds < 0) return QStringLiteral("无期限");
    const qint64 days = seconds / 86400;
    const int hours = static_cast<int>((seconds % 86400) / 3600);
    const int minutes = static_cast<int>((seconds % 3600) / 60);
    const int secs = static_cast<int>(seconds % 60);
    QStringList parts;
    if (days > 0) parts << QStringLiteral("%1 天").arg(days);
    if (hours > 0) parts << QStringLiteral("%1 小时").arg(hours);
    if (minutes > 0) parts << QStringLiteral("%1 分钟").arg(minutes);
    if (secs > 0 || parts.isEmpty()) parts << QStringLiteral("%1 秒").arg(secs);
    return parts.join(QStringLiteral(" "));
}

QString formatRuntimeDuration(qint64 seconds)
{
    const qint64 day = 24 * 60 * 60;
    if (seconds == 7 * day) return QStringLiteral("1 周（7 天）");
    if (seconds == 30 * day) return QStringLiteral("1 个月（按 30 天计算）");
    if (seconds == 90 * day) return QStringLiteral("3 个月（按 90 天计算）");
    if (seconds == 180 * day) return QStringLiteral("半年（按 180 天计算）");
    if (seconds == 365 * day) return QStringLiteral("1 年（按 365 天计算）");
    return formatDuration(seconds);
}

QString statusText(LicenseStatus status)
{
    switch (status) {
    case LicenseStatus::Valid: return QStringLiteral("有效");
    case LicenseStatus::FileMissing: return QStringLiteral("授权文件不存在");
    case LicenseStatus::FileTooLarge: return QStringLiteral("授权文件过大");
    case LicenseStatus::MalformedContainer: return QStringLiteral("授权文件格式错误");
    case LicenseStatus::UnsupportedVersion: return QStringLiteral("授权版本不受支持");
    case LicenseStatus::UnknownSigningKey: return QStringLiteral("未知签名密钥");
    case LicenseStatus::IssuerCertificateInvalid: return QStringLiteral("签发证书无效");
    case LicenseStatus::SignatureInvalid: return QStringLiteral("签名校验失败");
    case LicenseStatus::UnknownEncryptionKey: return QStringLiteral("未知加密密钥");
    case LicenseStatus::DecryptionFailed: return QStringLiteral("授权解密失败");
    case LicenseStatus::MalformedPayload: return QStringLiteral("授权内容格式错误");
    case LicenseStatus::ProductMismatch: return QStringLiteral("产品不匹配");
    case LicenseStatus::HardwareUnavailable: return QStringLiteral("无法读取硬件信息");
    case LicenseStatus::HardwareMismatch: return QStringLiteral("硬件不匹配");
    case LicenseStatus::NotYetValid: return QStringLiteral("尚未生效");
    case LicenseStatus::Expired: return QStringLiteral("已过期");
    case LicenseStatus::RuntimeQuotaExceeded: return QStringLiteral("应用实际运行时长已用尽");
    case LicenseStatus::ClockRollbackDetected: return QStringLiteral("检测到系统时间回拨");
    case LicenseStatus::ClockAnomaly: return QStringLiteral("检测到异常时间变化");
    case LicenseStatus::StateRollbackDetected: return QStringLiteral("检测到授权状态回滚");
    case LicenseStatus::StateCorrupt: return QStringLiteral("授权状态损坏");
    case LicenseStatus::CryptoUnavailable: return QStringLiteral("加密组件不可用");
    case LicenseStatus::IoError: return QStringLiteral("文件读写失败");
    case LicenseStatus::InternalError: return QStringLiteral("内部错误");
    }
    return QStringLiteral("未知状态");
}

QString licenseModeText(LicenseMode mode)
{
    switch (mode) {
    case LicenseMode::Perpetual: return QStringLiteral("永久授权");
    case LicenseMode::FixedExpiry: return QStringLiteral("固定日期授权");
    case LicenseMode::ValidityDuration: return QStringLiteral("签发后有效时长授权");
    case LicenseMode::RuntimeQuota: return QStringLiteral("应用实际运行时长授权");
    case LicenseMode::Hybrid: return QStringLiteral("固定日期 + 应用实际运行时长");
    }
    return QStringLiteral("未知模式");
}

QString bindingModeText(const HardwareBinding &binding)
{
    if (binding.mode == QLatin1String("all")) return QStringLiteral("全部硬件项必须匹配");
    if (binding.mode == QLatin1String("any")) return QStringLiteral("任一硬件项匹配即可");
    return QStringLiteral("至少匹配 %1 个硬件项").arg(binding.minimum);
}

QString hardwareTypeText(const QString &type)
{
    return HardwareFingerprint::typeDisplayName(type);
}

QString compactHash(const QString &hash)
{
    if (hash.size() <= 32) return hash;
    return hash.left(19) + QChar(0x2026) + hash.right(8);
}

QString humanReadableLicense(const LicenseDecision &decision, bool fullLocalCheck)
{
    QStringList lines;
    lines << QStringLiteral("验证结果")
          << QStringLiteral("────────")
          << QStringLiteral("状态：%1").arg(
                 !fullLocalCheck && decision.valid()
                 ? QStringLiteral("文件真实且内容完整") : statusText(decision.status))
          << QStringLiteral("说明：%1").arg(displayText(decision.message))
          << QStringLiteral("检查范围：%1").arg(fullLocalCheck
                 ? QStringLiteral("验签、解密、产品、当前电脑硬件、有效期及离线防回拨状态")
                 : QStringLiteral("仅验签、解密、产品及内容结构；未判断当前电脑能否使用"));

    const LicensePayload &payload = decision.payload;
    if (payload.licenseId.isEmpty()) {
        lines << QString() << QStringLiteral("未能安全读取授权内容。请按上方说明检查文件、产品和密钥库。");
        return lines.join(QLatin1Char('\n'));
    }

    lines << QString()
          << QStringLiteral("授权信息")
          << QStringLiteral("────────")
          << QStringLiteral("授权编号：%1").arg(payload.licenseId)
          << QStringLiteral("产品标识：%1").arg(payload.productId)
          << QStringLiteral("授权模式：%1").arg(licenseModeText(payload.licenseMode))
          << QStringLiteral("客户名称：%1").arg(displayText(payload.customerName))
          << QStringLiteral("客户编号：%1").arg(displayText(payload.customerId))
          << QStringLiteral("订单号：%1").arg(displayText(payload.orderId))
          << QStringLiteral("签发方：%1").arg(displayText(payload.issuer))
          << QStringLiteral("备注：%1").arg(displayText(payload.note));

    qint64 effectiveExpiry = payload.expiresAt;
    if (payload.licenseMode == LicenseMode::ValidityDuration
            && payload.maxRuntimeSeconds > 0) {
        effectiveExpiry = payload.issuedAt + payload.maxRuntimeSeconds;
    }

    lines << QString()
          << QStringLiteral("时间与额度")
          << QStringLiteral("────────")
          << QStringLiteral("签发时间：%1").arg(formatTimestamp(payload.issuedAt))
          << QStringLiteral("生效时间：%1").arg(
                 payload.notBefore >= 0 ? formatTimestamp(payload.notBefore)
                                        : QStringLiteral("签发后立即生效"))
          << QStringLiteral("到期时间：%1").arg(
                 effectiveExpiry >= 0 ? formatTimestamp(effectiveExpiry)
                                        : QStringLiteral("无期限"));
    if (effectiveExpiry >= 0) {
        const qint64 referenceUtc = decision.effectiveUtc > 0
                ? decision.effectiveUtc : QDateTime::currentSecsSinceEpoch();
        lines << (effectiveExpiry > referenceUtc
                  ? QStringLiteral("剩余期限：%1%2").arg(
                        formatDuration(effectiveExpiry - referenceUtc),
                        decision.effectiveUtc > 0 ? QString() : QStringLiteral("（按当前系统时间估算）"))
                  : QStringLiteral("剩余期限：已到期"));
    } else {
        lines << QStringLiteral("剩余期限：无期限");
    }
    if (payload.licenseMode == LicenseMode::ValidityDuration) {
        lines << QStringLiteral("签发后有效时长：%1")
                 .arg(formatRuntimeDuration(payload.maxRuntimeSeconds));
    } else if (payload.licenseMode == LicenseMode::RuntimeQuota
               || payload.licenseMode == LicenseMode::Hybrid) {
        lines << QStringLiteral("应用实际运行额度：%1")
                 .arg(formatRuntimeDuration(payload.maxRuntimeSeconds));
    }

    lines << QString()
          << QStringLiteral("授权功能")
          << QStringLiteral("────────")
          << (payload.features.isEmpty()
              ? QStringLiteral("未配置功能项")
              : QStringLiteral("• ") + payload.features.join(QStringLiteral("\n• ")));

    lines << QString()
          << QStringLiteral("硬件绑定")
          << QStringLiteral("────────")
          << QStringLiteral("匹配规则：%1").arg(bindingModeText(payload.binding))
          << QStringLiteral("要求匹配：%1 / %2 个硬件项")
             .arg(payload.binding.minimum).arg(payload.binding.bindingSlots.size());
    for (const BindingSlot &slot : payload.binding.bindingSlots) {
        QStringList hashes;
        for (const QString &hash : slot.acceptedHashes) hashes << compactHash(hash);
        lines << QStringLiteral("• %1（%2）：%3")
                 .arg(HardwareFingerprint::slotDisplayName(slot.slot),
                      hardwareTypeText(slot.type), hashes.join(QStringLiteral("，")));
    }

    lines << QString()
          << QStringLiteral("安全与格式")
          << QStringLiteral("────────")
          << QStringLiteral("签名密钥标识：%1").arg(displayText(decision.signingKeyId))
          << QStringLiteral("产品密钥标识：%1").arg(displayText(decision.encryptionKeyId))
          << QStringLiteral("状态代次：%1").arg(payload.stateEpoch)
          << QStringLiteral("授权文件格式版本：%1；硬件指纹版本：%2")
             .arg(payload.version).arg(payload.fingerprintVersion)
          << QString()
          << QStringLiteral("完整字段和完整硬件指纹见“完整技术数据”页。所有显示内容均来自已验签授权。");
    return lines.join(QLatin1Char('\n'));
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("Qt 离线授权签发工具"));
    resize(1050, 760);

    QTabWidget *tabs = new QTabWidget;
    tabs->addTab(createVaultPage(), QStringLiteral("密钥库"));
    tabs->addTab(createIssuePage(), QStringLiteral("单个授权"));
    tabs->addTab(createBatchPage(), QStringLiteral("批量授权"));
    tabs->addTab(createInspectPage(), QStringLiteral("读取授权"));
    setCentralWidget(tabs);
    statusBar()->showMessage(QStringLiteral("签发端永久离线运行"));
    m_autoLockTimer = new QTimer(this);
    m_autoLockTimer->setSingleShot(true);
    m_autoLockTimer->setInterval(10 * 60 * 1000);
    connect(m_autoLockTimer, &QTimer::timeout, this, &MainWindow::lockVault);
    updateModeControls();
}

MainWindow::~MainWindow()
{
    m_keys.clearSecrets();
}

QWidget *MainWindow::createVaultPage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);
    QFormLayout *form = new QFormLayout;
    m_vaultPath = new QLineEdit;
    m_vaultPassword = new QLineEdit;
    m_vaultPassword->setEchoMode(QLineEdit::Password);
    m_vaultPassword->setPlaceholderText(QStringLiteral("至少 10 个字符，不写入磁盘"));
    QWidget *passwordPanel = new QWidget;
    QVBoxLayout *passwordLayout = new QVBoxLayout(passwordPanel);
    passwordLayout->setContentsMargins(0, 0, 0, 0);
    passwordLayout->addWidget(m_vaultPassword);
    QLabel *passwordCount = new QLabel(QStringLiteral("当前 0 个字符"));
    passwordLayout->addWidget(passwordCount);
    connect(m_vaultPassword, &QLineEdit::textChanged, passwordCount,
            [passwordCount](const QString &text) {
        const int count = text.toUcs4().size();
        passwordCount->setText(QStringLiteral("当前 %1 个字符；至少需要 10 个字符").arg(count));
        passwordCount->setStyleSheet(count >= 10
                                     ? QStringLiteral("color:#0a7a24")
                                     : QStringLiteral("color:#b00020"));
    });
    m_productId = new QLineEdit;
    m_productId->setPlaceholderText(QStringLiteral("例如 DataProcessor；创建后不可修改"));
    m_productId->setToolTip(QStringLiteral(
        "目标应用的唯一标识，创建密钥库后不可修改。专业字段名：product_id"));
    QWidget *vaultPathPanel = new QWidget;
    QHBoxLayout *vaultPathLayout = new QHBoxLayout(vaultPathPanel);
    vaultPathLayout->setContentsMargins(0, 0, 0, 0);
    QPushButton *newVaultPathButton = new QPushButton(QStringLiteral("选择保存位置"));
    QPushButton *existingVaultButton = new QPushButton(QStringLiteral("选择已有密钥库"));
    vaultPathLayout->addWidget(m_vaultPath, 1);
    vaultPathLayout->addWidget(newVaultPathButton);
    vaultPathLayout->addWidget(existingVaultButton);
    connect(newVaultPathButton, &QPushButton::clicked,
            this, &MainWindow::browseNewVault);
    connect(existingVaultButton, &QPushButton::clicked,
            this, &MainWindow::browseExistingVault);
    form->addRow(QStringLiteral("密钥库"), vaultPathPanel);
    form->addRow(QStringLiteral("口令"), passwordPanel);
    form->addRow(QStringLiteral("产品标识"), m_productId);
    root->addLayout(form);

    QHBoxLayout *buttons = new QHBoxLayout;
    QPushButton *createButton = new QPushButton(QStringLiteral("创建密钥库"));
    QPushButton *openButton = new QPushButton(QStringLiteral("打开密钥库"));
    QPushButton *lockButton = new QPushButton(QStringLiteral("锁定密钥库"));
    QPushButton *exportButton = new QPushButton(QStringLiteral("导出运行端配置"));
    exportButton->setToolTip(QStringLiteral(
        "导出供目标应用运行时验证授权的 Runtime 配置"));
    connect(createButton, &QPushButton::clicked, this, &MainWindow::createVault);
    connect(openButton, &QPushButton::clicked, this, &MainWindow::openVault);
    connect(lockButton, &QPushButton::clicked, this, &MainWindow::lockVault);
    connect(exportButton, &QPushButton::clicked, this, &MainWindow::exportRuntimeConfig);
    buttons->addWidget(createButton);
    buttons->addWidget(openButton);
    buttons->addWidget(lockButton);
    buttons->addWidget(exportButton);
    buttons->addStretch();
    root->addLayout(buttons);

    m_vaultStatus = new QLabel(QStringLiteral("未打开密钥库"));
    m_vaultStatus->setWordWrap(true);
    root->addWidget(m_vaultStatus);
    QLabel *warning = new QLabel(QStringLiteral(
        "签名私钥只保存在加密密钥库。运行端配置包含根公钥和产品解密密钥，"
        "必须编译进目标应用，不能替代数字签名。"));
    warning->setWordWrap(true);
    root->addWidget(warning);
    root->addStretch();
    return page;
}

QWidget *MainWindow::createIssuePage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);

    QGroupBox *licenseBox = new QGroupBox(QStringLiteral("授权属性"));
    QFormLayout *form = new QFormLayout(licenseBox);
    m_customerId = new QLineEdit;
    m_customerName = new QLineEdit;
    m_orderId = new QLineEdit;
    m_licenseMode = new QComboBox;
    m_licenseMode->addItem(QStringLiteral("永久授权"), QStringLiteral("perpetual"));
    m_licenseMode->addItem(QStringLiteral("固定日期"), QStringLiteral("fixed_expiry"));
    m_licenseMode->addItem(QStringLiteral("签发后有效时长"), QStringLiteral("validity_duration"));
    m_licenseMode->addItem(QStringLiteral("应用实际运行时长"), QStringLiteral("runtime_quota"));
    m_licenseMode->addItem(QStringLiteral("固定日期 + 应用实际运行时长"), QStringLiteral("hybrid"));
    connect(m_licenseMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::updateModeControls);
    const QDateTime localNow = QDateTime::currentDateTime();
    m_expiry = new QDateTimeEdit(localNow.addYears(1));
    m_expiry->setTimeSpec(Qt::LocalTime);
    m_expiry->setCalendarPopup(true);
    m_expiry->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    QWidget *expiryPanel = new QWidget;
    QHBoxLayout *expiryLayout = new QHBoxLayout(expiryPanel);
    expiryLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *expiryZone = new QLabel(localZoneText(m_expiry->dateTime()));
    expiryLayout->addWidget(m_expiry, 1);
    expiryLayout->addWidget(expiryZone);
    connect(m_expiry, &QDateTimeEdit::dateTimeChanged, expiryZone,
            [expiryZone](const QDateTime &dateTime) {
        expiryZone->setText(localZoneText(dateTime));
    });
    m_notBeforeEnabled = new QCheckBox(QStringLiteral("指定生效时间"));
    m_notBefore = new QDateTimeEdit(localNow);
    m_notBefore->setTimeSpec(Qt::LocalTime);
    m_notBefore->setCalendarPopup(true);
    m_notBefore->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    QWidget *notBeforePanel = new QWidget;
    QHBoxLayout *notBeforeLayout = new QHBoxLayout(notBeforePanel);
    notBeforeLayout->setContentsMargins(0, 0, 0, 0);
    QLabel *notBeforeZone = new QLabel(localZoneText(m_notBefore->dateTime()));
    notBeforeLayout->addWidget(m_notBeforeEnabled);
    notBeforeLayout->addWidget(m_notBefore, 1);
    notBeforeLayout->addWidget(notBeforeZone);
    connect(m_notBefore, &QDateTimeEdit::dateTimeChanged, notBeforeZone,
            [notBeforeZone](const QDateTime &dateTime) {
        notBeforeZone->setText(localZoneText(dateTime));
    });
    connect(m_notBeforeEnabled, &QCheckBox::toggled,
            this, &MainWindow::updateModeControls);
    m_runtimePreset = new QComboBox;
    const int daySeconds = 24 * 60 * 60;
    m_runtimePreset->addItem(QStringLiteral("1 周（7 天）"), 7 * daySeconds);
    m_runtimePreset->addItem(QStringLiteral("1 个月（30 天）"), 30 * daySeconds);
    m_runtimePreset->addItem(QStringLiteral("3 个月（90 天）"), 90 * daySeconds);
    m_runtimePreset->addItem(QStringLiteral("半年（180 天）"), 180 * daySeconds);
    m_runtimePreset->addItem(QStringLiteral("1 年（365 天）"), 365 * daySeconds);
    m_runtimePreset->addItem(QStringLiteral("自定义秒数"), -1);
    m_runtimePreset->setCurrentIndex(1);
    m_runtimePreset->setToolTip(QStringLiteral(
        "累计应用实际运行时间；月份和年份按选项中标明的固定天数折算。"));
    QWidget *runtimePanel = new QWidget;
    QHBoxLayout *runtimeLayout = new QHBoxLayout(runtimePanel);
    runtimeLayout->setContentsMargins(0, 0, 0, 0);
    m_runtimeSeconds = new QSpinBox;
    m_runtimeSeconds->setRange(1, 2000000000);
    m_runtimeSeconds->setValue(30 * 24 * 60 * 60);
    m_runtimeSeconds->setSuffix(QStringLiteral(" 秒"));
    m_runtimeSeconds->setVisible(false);
    QLabel *runtimeSummary = new QLabel(formatRuntimeDuration(m_runtimeSeconds->value()));
    runtimeSummary->setVisible(false);
    runtimeLayout->addWidget(m_runtimePreset);
    runtimeLayout->addWidget(m_runtimeSeconds);
    runtimeLayout->addWidget(runtimeSummary);
    runtimeLayout->addStretch();
    connect(m_runtimePreset, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this, runtimeSummary](int) {
        const int presetSeconds = m_runtimePreset->currentData().toInt();
        const bool custom = presetSeconds < 0;
        if (!custom) m_runtimeSeconds->setValue(presetSeconds);
        m_runtimeSeconds->setVisible(custom);
        m_runtimeSeconds->setEnabled(custom && m_runtimePreset->isEnabled());
        runtimeSummary->setVisible(custom);
        runtimeSummary->setText(formatRuntimeDuration(m_runtimeSeconds->value()));
    });
    connect(m_runtimeSeconds, QOverload<int>::of(&QSpinBox::valueChanged),
            runtimeSummary, [runtimeSummary](int seconds) {
        runtimeSummary->setText(formatRuntimeDuration(seconds));
    });
    m_features = new QLineEdit(QStringLiteral("basic"));
    m_features->setPlaceholderText(QStringLiteral("basic,export,chart"));
    m_features->setToolTip(QStringLiteral(
        "填写目标应用定义的功能项标识，多个功能项可用逗号、分号或空格分隔。"));
    m_note = new QLineEdit;
    m_note->setMaxLength(2048);
    m_note->setPlaceholderText(QStringLiteral("可选；例如合同、设备用途或售后说明"));
    form->addRow(QStringLiteral("客户编号"), m_customerId);
    form->addRow(QStringLiteral("客户名称"), m_customerName);
    form->addRow(QStringLiteral("订单号"), m_orderId);
    form->addRow(QStringLiteral("授权模式"), m_licenseMode);
    form->addRow(QStringLiteral("生效时间（本机）"), notBeforePanel);
    form->addRow(QStringLiteral("到期时间（本机）"), expiryPanel);
    m_runtimeLabel = new QLabel(QStringLiteral("时长 / 额度"));
    form->addRow(m_runtimeLabel, runtimePanel);
    form->addRow(QStringLiteral("授权功能项"), m_features);
    form->addRow(QStringLiteral("授权备注"), m_note);
    root->addWidget(licenseBox);

    QGroupBox *hardwareBox = new QGroupBox(QStringLiteral("硬件绑定"));
    QVBoxLayout *hardwareLayout = new QVBoxLayout(hardwareBox);
    QHBoxLayout *policy = new QHBoxLayout;
    m_bindingMode = new QComboBox;
    m_bindingMode->addItem(QStringLiteral("全部匹配"), QStringLiteral("all"));
    m_bindingMode->addItem(QStringLiteral("任一匹配"), QStringLiteral("any"));
    m_bindingMode->addItem(QStringLiteral("阈值匹配"), QStringLiteral("threshold"));
    m_minimum = new QSpinBox;
    m_minimum->setRange(1, 64);
    policy->addWidget(new QLabel(QStringLiteral("匹配规则")));
    policy->addWidget(m_bindingMode);
    policy->addWidget(new QLabel(QStringLiteral("至少匹配数量")));
    policy->addWidget(m_minimum);
    policy->addStretch();
    hardwareLayout->addLayout(policy);

    m_hardwareTable = new QTableWidget(0, 4);
    m_hardwareTable->setHorizontalHeaderLabels(
                QStringList() << QStringLiteral("使用") << QStringLiteral("硬件项目")
                              << QStringLiteral("识别方式") << QStringLiteral("硬件值或匿名指纹"));
    m_hardwareTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_hardwareTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_hardwareTable->setToolTip(QStringLiteral(
        "悬浮硬件项目或识别方式可查看专业字段名。硬件值也可填写采集器生成的 SHA-256 匿名指纹。"));
    hardwareLayout->addWidget(m_hardwareTable);
    QHBoxLayout *hardwareButtons = new QHBoxLayout;
    QPushButton *collectButton = new QPushButton(QStringLiteral("采集本机"));
    QPushButton *addButton = new QPushButton(QStringLiteral("添加硬件项"));
    QPushButton *importButton = new QPushButton(QStringLiteral("导入硬件请求"));
    importButton->setToolTip(QStringLiteral("导入 .qreq 硬件请求文件"));
    connect(collectButton, &QPushButton::clicked, this, &MainWindow::collectHardware);
    connect(addButton, &QPushButton::clicked, this, &MainWindow::addHardwareRow);
    connect(importButton, &QPushButton::clicked, this, &MainWindow::importHardwareRequest);
    hardwareButtons->addWidget(collectButton);
    hardwareButtons->addWidget(addButton);
    hardwareButtons->addWidget(importButton);
    hardwareButtons->addStretch();
    hardwareLayout->addLayout(hardwareButtons);
    root->addWidget(hardwareBox, 1);

    m_licenseOutput = new QLineEdit;
    m_licenseOutput->setPlaceholderText(QStringLiteral("授权文件保存位置"));
    root->addWidget(pathRow(m_licenseOutput, QStringLiteral("选择输出"),
                            this, SLOT(browseLicenseOutput())));
    QPushButton *issueButton = new QPushButton(QStringLiteral("生成并自验证授权"));
    connect(issueButton, &QPushButton::clicked, this, &MainWindow::issueLicense);
    root->addWidget(issueButton);
    return page;
}

QWidget *MainWindow::createBatchPage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);
    QFormLayout *form = new QFormLayout;
    m_batchInput = new QLineEdit;
    m_batchOutput = new QLineEdit;
    m_batchInput->setToolTip(QStringLiteral("支持 CSV 或 JSON 格式的批量授权数据"));
    form->addRow(QStringLiteral("批量数据文件"),
                  pathRow(m_batchInput, QStringLiteral("选择"), this, SLOT(browseBatchInput())));
    form->addRow(QStringLiteral("授权文件输出目录"),
                  pathRow(m_batchOutput, QStringLiteral("选择"), this, SLOT(browseBatchOutput())));
    root->addLayout(form);
    QPushButton *button = new QPushButton(QStringLiteral("预检、批量生成并原子发布"));
    connect(button, &QPushButton::clicked, this, &MainWindow::issueBatch);
    root->addWidget(button);
    m_batchResult = new QTextEdit;
    m_batchResult->setReadOnly(true);
    root->addWidget(m_batchResult, 1);
    return page;
}

QWidget *MainWindow::createInspectPage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);
    m_inspectPath = new QLineEdit;
    root->addWidget(pathRow(m_inspectPath, QStringLiteral("选择授权"),
                            this, SLOT(browseInspectLicense())));
    m_fullLocalCheck = new QCheckBox(QStringLiteral(
        "同时校验此电脑的硬件、有效期与离线防回拨状态（读取客户授权时通常不勾选）"));
    root->addWidget(m_fullLocalCheck);
    QPushButton *button = new QPushButton(QStringLiteral("验签、解密并读取"));
    connect(button, &QPushButton::clicked, this, &MainWindow::inspectLicense);
    root->addWidget(button);
    QTabWidget *resultTabs = new QTabWidget;
    m_inspectResult = new QTextEdit;
    m_inspectResult->setReadOnly(true);
    m_inspectResult->setPlaceholderText(QStringLiteral("选择授权文件后点击“验签、解密并读取”。"));
    m_inspectRawJson = new QTextEdit;
    m_inspectRawJson->setReadOnly(true);
    resultTabs->addTab(m_inspectResult, QStringLiteral("授权概览"));
    const int technicalTab = resultTabs->addTab(
                m_inspectRawJson, QStringLiteral("完整技术数据"));
    resultTabs->setTabToolTip(technicalTab, QStringLiteral(
        "显示原始 JSON 字段，供开发、排障和审计使用"));
    root->addWidget(resultTabs, 1);
    return page;
}

void MainWindow::browseNewVault()
{
    QString path = QFileDialog::getSaveFileName(
                this, QStringLiteral("选择新密钥库的保存位置"),
                QStringLiteral("issuer.qtkv"), QStringLiteral("密钥库文件 (*.qtkv)"));
    if (!path.isEmpty() && !path.endsWith(QLatin1String(".qtkv"), Qt::CaseInsensitive)) {
        path += QStringLiteral(".qtkv");
    }
    if (!path.isEmpty()) m_vaultPath->setText(path);
}

void MainWindow::browseExistingVault()
{
    const QString path = QFileDialog::getOpenFileName(
                this, QStringLiteral("选择已有密钥库"), QString(),
                QStringLiteral("密钥库文件 (*.qtkv)"));
    if (!path.isEmpty()) m_vaultPath->setText(path);
}

void MainWindow::createVault()
{
    if (m_vaultPath->text().trimmed().isEmpty()) browseNewVault();
    QString vaultPath = m_vaultPath->text().trimmed();
    const QString productId = m_productId->text().trimmed();
    const int passwordCharacters = m_vaultPassword->text().toUcs4().size();
    if (vaultPath.isEmpty()) {
        setVaultStatus(QStringLiteral("请选择新密钥库的保存路径。"), true);
        return;
    }
    if (QFileInfo::exists(vaultPath)) {
        setVaultStatus(QStringLiteral(
                           "该路径已存在文件。若它是已创建的密钥库，请使用“打开密钥库”；否则请选择新文件名。"),
                       true);
        return;
    }
    if (passwordCharacters < 10) {
        setVaultStatus(QStringLiteral("口令当前为 %1 个字符，至少需要 10 个字符。")
                       .arg(passwordCharacters), true);
        return;
    }
    if (!QRegularExpression(QStringLiteral("^[A-Za-z0-9._-]{1,128}$"))
            .match(productId).hasMatch()) {
        setVaultStatus(QStringLiteral(
                           "产品标识必须为 1–128 个英文字符，仅允许字母、数字、点、下划线和连字符。"),
                       true);
        return;
    }
    m_keys.clearSecrets();
    QString error;
    QByteArray vaultPassword = m_vaultPassword->text().toUtf8();
    const bool created = KeyVault::create(vaultPath, vaultPassword, productId, &m_keys, &error);
    CryptoProvider::wipe(vaultPassword);
    m_vaultPassword->clear();
    if (!created) {
        setVaultStatus(error, true);
        return;
    }
    QString status = QStringLiteral("已创建并打开。签名密钥标识：%1；产品密钥标识：%2")
            .arg(m_keys.keyId, m_keys.encryptionKeyId);
    if (!m_keys.secretsMemoryLocked) {
        status += QStringLiteral("\n警告：操作系统拒绝锁定敏感内存；密钥库可正常使用，但应关闭交换文件并限制签发机访问。");
    }
    setVaultStatus(status, !m_keys.secretsMemoryLocked);
    m_autoLockTimer->start();
}

void MainWindow::openVault()
{
    if (!QFileInfo(m_vaultPath->text().trimmed()).isFile()) browseExistingVault();
    if (!QFileInfo(m_vaultPath->text().trimmed()).isFile()) {
        setVaultStatus(QStringLiteral("请选择一个现有的密钥库文件。"), true);
        return;
    }
    m_keys.clearSecrets();
    QString error;
    QByteArray vaultPassword = m_vaultPassword->text().toUtf8();
    const bool opened = KeyVault::open(m_vaultPath->text(), vaultPassword, &m_keys, &error);
    CryptoProvider::wipe(vaultPassword);
    m_vaultPassword->clear();
    if (!opened) {
        setVaultStatus(error, true);
        return;
    }
    m_productId->setText(m_keys.productId);
    QString status = QStringLiteral("已打开。签名密钥标识：%1；产品密钥标识：%2")
            .arg(m_keys.keyId, m_keys.encryptionKeyId);
    if (!m_keys.secretsMemoryLocked) {
        status += QStringLiteral("\n警告：操作系统拒绝锁定敏感内存；密钥库可正常使用，但应关闭交换文件并限制签发机访问。");
    }
    setVaultStatus(status, !m_keys.secretsMemoryLocked);
    m_autoLockTimer->start();
}

void MainWindow::lockVault()
{
    m_keys.clearSecrets();
    m_vaultPassword->clear();
    if (m_autoLockTimer) m_autoLockTimer->stop();
    setVaultStatus(QStringLiteral("密钥库已锁定；私钥和产品密钥已从活动内存清零。"));
}

void MainWindow::exportRuntimeConfig()
{
    if (!requireOpenVault()) return;
    const QString path = QFileDialog::getSaveFileName(
                this, QStringLiteral("导出运行端配置"), QStringLiteral("runtime-config.json"),
                QStringLiteral("运行端配置文件 (*.json)"));
    if (path.isEmpty()) return;
    QString error;
    const QString headerPath = QFileInfo(path).dir().filePath(QStringLiteral("qtlicense_runtime_config.h"));
    if (!KeyVault::exportRuntimeJson(path, m_keys, &error)
            || !KeyVault::exportRuntimeHeader(headerPath, m_keys, &error)) {
        QMessageBox::critical(this, QStringLiteral("导出失败"), error);
        return;
    }
    QMessageBox::information(this, QStringLiteral("导出完成"),
                             QStringLiteral("已生成：\n%1\n%2").arg(path, headerPath));
}

void MainWindow::collectHardware()
{
    QStringList warnings;
    const QVector<HardwareValue> values = HardwareFingerprint::collect(&warnings);
    for (const HardwareValue &value : values) appendHardware(value);
    m_minimum->setMaximum(qMax(1, m_hardwareTable->rowCount()));
    if (!warnings.isEmpty()) statusBar()->showMessage(warnings.join(QStringLiteral("；")), 10000);
}

void MainWindow::addHardwareRow()
{
    HardwareValue value;
    value.slot = QStringLiteral("custom-%1").arg(m_hardwareTable->rowCount() + 1);
    value.type = QStringLiteral("board");
    appendHardware(value);
}

void MainWindow::importHardwareRequest()
{
    const QString path = QFileDialog::getOpenFileName(
                this, QStringLiteral("导入硬件请求"), QString(),
                QStringLiteral("硬件请求文件 (*.qreq *.json)"));
    if (path.isEmpty()) return;
    QFile file(path);
    QJsonParseError parseError;
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, QStringLiteral("导入失败"), QStringLiteral("无法读取文件"));
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    QString product;
    QVector<HardwareValue> values;
    QString error;
    if (parseError.error != QJsonParseError::NoError || !document.isObject()
            || !HardwareFingerprint::requestFromJson(document.object(), &product, &values, &error)) {
        QMessageBox::critical(this, QStringLiteral("导入失败"),
                              error.isEmpty() ? parseError.errorString() : error);
        return;
    }
    if (m_keys.isComplete() && product != m_keys.productId) {
        QMessageBox::critical(this, QStringLiteral("导入失败"), QStringLiteral("硬件请求产品不匹配"));
        return;
    }
    for (const HardwareValue &value : values) appendHardware(value);
}

void MainWindow::browseLicenseOutput()
{
    const QString path = QFileDialog::getSaveFileName(
                this, QStringLiteral("授权输出"), QStringLiteral("license.qtlic"),
                QStringLiteral("授权文件 (*.qtlic)"));
    if (!path.isEmpty()) m_licenseOutput->setText(path);
}

void MainWindow::issueLicense()
{
    if (!requireOpenVault()) return;
    QString error;
    const QVector<HardwareValue> hardware = selectedHardware(&error);
    if (hardware.isEmpty()) {
        QMessageBox::critical(this, QStringLiteral("生成失败"), error);
        return;
    }

    LicensePayload payload;
    payload.licenseId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    payload.productId = m_keys.productId;
    payload.customerId = m_customerId->text().trimmed();
    payload.customerName = m_customerName->text().trimmed();
    payload.orderId = m_orderId->text().trimmed();
    payload.issuedAt = QDateTime::currentSecsSinceEpoch();
    if (!licenseModeFromString(m_licenseMode->currentData().toString(), &payload.licenseMode)) {
        QMessageBox::critical(this, QStringLiteral("生成失败"), QStringLiteral("授权模式无效"));
        return;
    }
    if (payload.licenseMode == LicenseMode::FixedExpiry
            || payload.licenseMode == LicenseMode::Hybrid) {
        payload.expiresAt = m_expiry->dateTime().toUTC().toSecsSinceEpoch();
    }
    if (m_notBeforeEnabled->isChecked()) {
        payload.notBefore = m_notBefore->dateTime().toUTC().toSecsSinceEpoch();
    }
    if (payload.licenseMode == LicenseMode::ValidityDuration
            || payload.licenseMode == LicenseMode::RuntimeQuota
            || payload.licenseMode == LicenseMode::Hybrid) {
        payload.maxRuntimeSeconds = m_runtimeSeconds->value();
    }
    payload.features = m_features->text().split(
                QRegularExpression(QStringLiteral("[,;|\\s]+")), QString::SkipEmptyParts);
    payload.features.removeDuplicates();
    payload.features.sort();
    payload.issuer = QStringLiteral("QtLicenseIssuer");
    payload.note = m_note->text().trimmed();
    payload.binding = HardwareFingerprint::bindingFromValues(
                hardware, m_bindingMode->currentData().toString(), m_minimum->value(), &error);
    if (!LicenseCodec::issueToFile(payload, m_keys, m_licenseOutput->text(), &error)) {
        QMessageBox::critical(this, QStringLiteral("生成失败"), error);
        return;
    }
    QString timeSummary = QStringLiteral("\n签发时间：%1")
            .arg(formatTimestamp(payload.issuedAt));
    if (payload.notBefore >= 0) {
        timeSummary += QStringLiteral("\n生效时间：%1").arg(formatTimestamp(payload.notBefore));
    } else {
        timeSummary += QStringLiteral("\n生效时间：签发后立即生效");
    }
    qint64 effectiveExpiry = payload.expiresAt;
    if (payload.licenseMode == LicenseMode::ValidityDuration) {
        effectiveExpiry = payload.issuedAt + payload.maxRuntimeSeconds;
    }
    if (effectiveExpiry >= 0) {
        timeSummary += QStringLiteral("\n到期时间：%1\n签发至到期：%2")
                .arg(formatTimestamp(effectiveExpiry),
                     formatDuration(effectiveExpiry - payload.issuedAt));
    } else if (payload.licenseMode == LicenseMode::RuntimeQuota) {
        timeSummary += QStringLiteral("\n到期时间：不按自然时间，仅累计应用实际运行时间");
    } else {
        timeSummary += QStringLiteral("\n到期时间：无期限");
    }
    if (payload.licenseMode == LicenseMode::ValidityDuration) {
        timeSummary += QStringLiteral("\n签发后有效时长：%1")
                .arg(formatRuntimeDuration(payload.maxRuntimeSeconds));
    } else if (payload.licenseMode == LicenseMode::RuntimeQuota
               || payload.licenseMode == LicenseMode::Hybrid) {
        timeSummary += QStringLiteral("\n应用实际运行额度：%1")
                .arg(formatRuntimeDuration(payload.maxRuntimeSeconds));
    }
    QMessageBox::information(this, QStringLiteral("生成成功"),
                             QStringLiteral("授权编号：%1\n文件：%2%3")
                             .arg(payload.licenseId, m_licenseOutput->text(), timeSummary));
}

void MainWindow::updateModeControls()
{
    if (!m_licenseMode) return;
    LicenseMode mode;
    licenseModeFromString(m_licenseMode->currentData().toString(), &mode);
    const bool supportsStartTime = mode != LicenseMode::Perpetual;
    m_notBeforeEnabled->setEnabled(supportsStartTime);
    if (!supportsStartTime) m_notBeforeEnabled->setChecked(false);
    m_notBefore->setEnabled(supportsStartTime && m_notBeforeEnabled->isChecked());
    m_expiry->setEnabled(mode == LicenseMode::FixedExpiry || mode == LicenseMode::Hybrid);
    const bool usesDuration = mode == LicenseMode::ValidityDuration
            || mode == LicenseMode::RuntimeQuota || mode == LicenseMode::Hybrid;
    if (mode == LicenseMode::ValidityDuration) {
        m_runtimeLabel->setText(QStringLiteral("签发后有效时长"));
    } else if (mode == LicenseMode::RuntimeQuota || mode == LicenseMode::Hybrid) {
        m_runtimeLabel->setText(QStringLiteral("应用实际运行额度"));
    } else {
        m_runtimeLabel->setText(QStringLiteral("时长 / 额度"));
    }
    m_runtimePreset->setEnabled(usesDuration);
    m_runtimeSeconds->setEnabled(usesDuration && m_runtimePreset->currentData().toInt() < 0);
}

void MainWindow::browseBatchInput()
{
    const QString path = QFileDialog::getOpenFileName(
                this, QStringLiteral("选择批量输入"), QString(),
                QStringLiteral("批量数据文件 (*.csv *.json)"));
    if (!path.isEmpty()) m_batchInput->setText(path);
}

void MainWindow::browseBatchOutput()
{
    const QString parent = QFileDialog::getExistingDirectory(this, QStringLiteral("选择父目录"));
    if (!parent.isEmpty()) {
        m_batchOutput->setText(QDir(parent).filePath(
                                  QStringLiteral("batch-%1")
                                  .arg(QDateTime::currentDateTimeUtc().toString("yyyyMMdd-HHmmss"))));
    }
}

void MainWindow::issueBatch()
{
    if (!requireOpenVault()) return;
    BatchIssueResult result;
    QString error;
    if (!BatchIssuer::issueFile(m_batchInput->text(), m_batchOutput->text(),
                                m_keys, &result, &error)) {
        m_batchResult->setPlainText(QStringLiteral("失败：") + error);
        return;
    }
    m_batchResult->setPlainText(QStringLiteral("批次成功\n批次编号：%1\n生成数量：%2\n输出目录：%3")
                                 .arg(result.batchId)
                                .arg(result.issuedCount)
                                .arg(result.outputDirectory));
}

void MainWindow::browseInspectLicense()
{
    const QString path = QFileDialog::getOpenFileName(
                this, QStringLiteral("选择授权"), QString(),
                QStringLiteral("授权文件 (*.qtlic)"));
    if (!path.isEmpty()) m_inspectPath->setText(path);
}

void MainWindow::inspectLicense()
{
    if (!requireOpenVault()) return;
    QHash<QString, QByteArray> keys;
    keys.insert(m_keys.encryptionKeyId, m_keys.productEncryptionKey);
    LicenseDecision decision;
    if (m_fullLocalCheck->isChecked()) {
        VerifyOptions options;
        options.productId = m_keys.productId;
        options.licensePath = m_inspectPath->text();
        options.rootPublicKey = m_keys.rootPublicKey;
        options.productDecryptionKeys = keys;
        decision = LicenseCodec::verifyFile(options);
    } else {
        decision = LicenseCodec::verifyContainer(
                    m_inspectPath->text(), m_keys.productId, m_keys.rootPublicKey, keys);
    }
    m_inspectResult->setPlainText(humanReadableLicense(decision, m_fullLocalCheck->isChecked()));
    m_inspectRawJson->setPlainText(rawPayloadText(decision, m_fullLocalCheck->isChecked()));
}

QVector<HardwareValue> MainWindow::selectedHardware(QString *error) const
{
    QVector<HardwareValue> result;
    for (int row = 0; row < m_hardwareTable->rowCount(); ++row) {
        const QTableWidgetItem *selected = m_hardwareTable->item(row, 0);
        if (!selected || selected->checkState() != Qt::Checked) continue;
        HardwareValue value;
        value.slot = hardwareTechnicalValue(m_hardwareTable->item(row, 1));
        value.type = hardwareTechnicalValue(m_hardwareTable->item(row, 2));
        const QString input = m_hardwareTable->item(row, 3)->text().trimmed();
        if (input.startsWith(QLatin1String("sha256:"))) value.hash = input;
        else value.value = input;
        if (value.slot.isEmpty() || value.type.isEmpty()
                || (value.value.isEmpty() && value.hash.isEmpty())) {
            if (error) *error = QStringLiteral("第 %1 行硬件信息不完整").arg(row + 1);
            return QVector<HardwareValue>();
        }
        if (!value.value.isEmpty() && !HardwareFingerprint::isUsable(value.type, value.value, error)) {
            return QVector<HardwareValue>();
        }
        result.append(value);
    }
    if (result.isEmpty() && error) *error = QStringLiteral("至少选择一个有效硬件绑定项");
    return result;
}

void MainWindow::appendHardware(const HardwareValue &value, bool selected)
{
    const int row = m_hardwareTable->rowCount();
    m_hardwareTable->insertRow(row);
    QTableWidgetItem *use = new QTableWidgetItem;
    use->setFlags(Qt::ItemIsEnabled | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
    use->setCheckState(selected ? Qt::Checked : Qt::Unchecked);
    m_hardwareTable->setItem(row, 0, use);
    m_hardwareTable->setItem(row, 1, hardwareKeyItem(
                                 HardwareFingerprint::slotDisplayName(value.slot), value.slot));
    m_hardwareTable->setItem(row, 2, hardwareKeyItem(
                                 HardwareFingerprint::typeDisplayName(value.type), value.type));
    QTableWidgetItem *hardwareValue = new QTableWidgetItem(
                value.hash.isEmpty() ? value.value : value.hash);
    if (!value.hash.isEmpty()) {
        hardwareValue->setToolTip(QStringLiteral(
            "采集器生成的 SHA-256 匿名指纹；不包含原始硬件值。"));
    }
    m_hardwareTable->setItem(row, 3, hardwareValue);
    m_minimum->setMaximum(qMax(1, m_hardwareTable->rowCount()));
}

bool MainWindow::requireOpenVault()
{
    if (m_keys.isComplete()) {
        if (m_autoLockTimer) m_autoLockTimer->start();
        return true;
    }
    QMessageBox::warning(this, QStringLiteral("未打开密钥库"),
                         QStringLiteral("请先创建或打开密钥库。"));
    return false;
}

void MainWindow::setVaultStatus(const QString &text, bool error)
{
    m_vaultStatus->setText(text);
    m_vaultStatus->setStyleSheet(error ? QStringLiteral("color:#b00020")
                                       : QStringLiteral("color:#0a7a24"));
}
