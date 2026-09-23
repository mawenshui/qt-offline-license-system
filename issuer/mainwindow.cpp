#include "mainwindow.h"

#include "audit_logger.h"
#include "batch_issuer.h"
#include "crypto_provider.h"
#include "hardware_fingerprint.h"
#include "key_vault.h"
#include "license_codec.h"
#include "qt_license_theme.h"
#include "runtime_compatibility.h"

#include <QAbstractButton>
#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QInputDialog>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <QWizard>
#include <QWizardPage>

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
    ui::setButtonRole(button, "secondary");
    layout->addWidget(edit, 1);
    layout->addWidget(button);
    QObject::connect(button, SIGNAL(clicked()), receiver, slot);
    return widget;
}

void setInvalid(QWidget *widget, bool invalid)
{
    if (!widget || widget->property("invalid").toBool() == invalid) return;
    widget->setProperty("invalid", invalid);
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    widget->update();
}

QWizardPage *onboardingPage(const QString &title, const QString &introduction,
                            const QStringList &steps)
{
    QWizardPage *page = new QWizardPage;
    page->setTitle(title);
    QVBoxLayout *layout = new QVBoxLayout(page);
    QLabel *intro = new QLabel(introduction);
    intro->setWordWrap(true);
    layout->addWidget(intro);
    layout->addSpacing(8);
    for (const QString &step : steps) {
        QLabel *line = new QLabel(QStringLiteral("• ") + step);
        line->setWordWrap(true);
        layout->addWidget(line);
    }
    layout->addStretch();
    return page;
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
    resize(1120, 820);
    setMinimumSize(900, 680);

    QWidget *shell = new QWidget;
    shell->setObjectName(QStringLiteral("AppShell"));
    QVBoxLayout *shellLayout = new QVBoxLayout(shell);
    shellLayout->setContentsMargins(24, 22, 24, 18);
    shellLayout->setSpacing(16);
    ui::addApplicationHeader(
                shellLayout, QStringLiteral("安全离线签发"),
                QStringLiteral("离线授权控制台"),
                QStringLiteral("在受控离线环境中管理密钥、签发授权并核验授权内容。"),
                QStringLiteral("永久离线 · 10 分钟自动锁定"));
    m_tabs = new QTabWidget;
    m_tabs->setObjectName(QStringLiteral("mainTabs"));
    m_tabs->setDocumentMode(true);
    m_tabs->addTab(createVaultPage(), QStringLiteral("密钥库"));
    m_tabs->addTab(createIssuePage(), QStringLiteral("单个授权"));
    m_tabs->addTab(createBatchPage(), QStringLiteral("批量授权"));
    m_tabs->addTab(createInspectPage(), QStringLiteral("读取授权"));
    shellLayout->addWidget(m_tabs, 1);
    setCentralWidget(shell);
    QAction *guideAction = menuBar()->addAction(QStringLiteral("首次使用向导"));
    connect(guideAction, &QAction::triggered, this, &MainWindow::showFirstRunWizard);
    statusBar()->showMessage(QStringLiteral("安全模式：签发端永久离线运行"));
    m_autoLockTimer = new QTimer(this);
    m_autoLockTimer->setSingleShot(true);
    m_autoLockTimer->setInterval(10 * 60 * 1000);
    connect(m_autoLockTimer, &QTimer::timeout, this, &MainWindow::lockVault);
    m_lockCountdownTimer = new QTimer(this);
    m_lockCountdownTimer->setInterval(1000);
    connect(m_lockCountdownTimer, &QTimer::timeout,
            this, &MainWindow::updateAutoLockCountdown);
    updateModeControls();
    updateVaultControls();

    const QSettings settings;
    if (!settings.value(QStringLiteral("onboarding/completed"), false).toBool()
            && qEnvironmentVariableIsEmpty("QTLIC_SKIP_ONBOARDING")) {
        QTimer::singleShot(0, this, &MainWindow::showFirstRunWizard);
    }
}

MainWindow::~MainWindow()
{
    m_keys.clearSecrets();
}

QWidget *MainWindow::createVaultPage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);
    root->setContentsMargins(18, 20, 18, 18);
    root->setSpacing(15);
    ui::addPageHeader(root, QStringLiteral("密钥安全"),
                      QStringLiteral("密钥库管理"),
                      QStringLiteral("创建或打开加密密钥库。离开签发机前请主动锁定并安全备份。"));
    QGroupBox *vaultBox = new QGroupBox(QStringLiteral("密钥库设置"));
    QFormLayout *form = new QFormLayout(vaultBox);
    form->setHorizontalSpacing(16);
    form->setVerticalSpacing(10);
    m_vaultPath = new QLineEdit;
    m_vaultPassword = new QLineEdit;
    m_vaultPassword->setEchoMode(QLineEdit::Password);
    m_vaultPassword->setPlaceholderText(QStringLiteral("至少 10 个字符，不写入磁盘"));
    QWidget *passwordPanel = new QWidget;
    QVBoxLayout *passwordLayout = new QVBoxLayout(passwordPanel);
    passwordLayout->setContentsMargins(0, 0, 0, 0);
    passwordLayout->addWidget(m_vaultPassword);
    QLabel *passwordCount = new QLabel(QStringLiteral("当前 0 个字符"));
    passwordCount->setProperty("role", "counter");
    passwordCount->setProperty("state", "invalid");
    passwordLayout->addWidget(passwordCount);
    connect(m_vaultPassword, &QLineEdit::textChanged, passwordCount,
            [passwordCount](const QString &text) {
        const int count = text.toUcs4().size();
        passwordCount->setText(QStringLiteral("当前 %1 个字符；至少需要 10 个字符").arg(count));
        passwordCount->setProperty("state", count >= 10 ? "valid" : "invalid");
        passwordCount->style()->unpolish(passwordCount);
        passwordCount->style()->polish(passwordCount);
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
    root->addWidget(vaultBox);

    QHBoxLayout *buttons = new QHBoxLayout;
    QPushButton *createButton = new QPushButton(QStringLiteral("创建密钥库"));
    QPushButton *openButton = new QPushButton(QStringLiteral("打开密钥库"));
    QPushButton *lockButton = new QPushButton(QStringLiteral("锁定密钥库"));
    m_exportRuntimeButton = new QPushButton(QStringLiteral("导出运行端配置"));
    createButton->setObjectName(QStringLiteral("createVaultButton"));
    openButton->setObjectName(QStringLiteral("openVaultButton"));
    lockButton->setObjectName(QStringLiteral("lockVaultButton"));
    m_exportRuntimeButton->setObjectName(QStringLiteral("exportRuntimeButton"));
    ui::setButtonRole(createButton, "accent");
    ui::setButtonRole(openButton, "primary");
    ui::setButtonRole(lockButton, "danger");
    m_exportRuntimeButton->setToolTip(QStringLiteral(
        "导出供目标应用运行时验证授权的 Runtime 配置"));
    connect(createButton, &QPushButton::clicked, this, &MainWindow::createVault);
    connect(openButton, &QPushButton::clicked, this, &MainWindow::openVault);
    connect(lockButton, &QPushButton::clicked, this, &MainWindow::lockVault);
    connect(m_exportRuntimeButton, &QPushButton::clicked,
            this, &MainWindow::exportRuntimeConfig);
    buttons->addWidget(createButton);
    buttons->addWidget(openButton);
    buttons->addWidget(lockButton);
    buttons->addWidget(m_exportRuntimeButton);
    buttons->addStretch();
    root->addLayout(buttons);

    QHBoxLayout *safetyButtons = new QHBoxLayout;
    QPushButton *backupButton = new QPushButton(QStringLiteral("复制加密备份"));
    QPushButton *verifyBackupButton = new QPushButton(QStringLiteral("验证备份可恢复"));
    QPushButton *verifyAuditButton = new QPushButton(QStringLiteral("验证审计日志"));
    backupButton->setObjectName(QStringLiteral("backupVaultButton"));
    verifyBackupButton->setObjectName(QStringLiteral("verifyBackupButton"));
    verifyAuditButton->setObjectName(QStringLiteral("verifyAuditButton"));
    connect(backupButton, &QPushButton::clicked, this, &MainWindow::backupVault);
    connect(verifyBackupButton, &QPushButton::clicked,
            this, &MainWindow::verifyVaultBackup);
    connect(verifyAuditButton, &QPushButton::clicked,
            this, &MainWindow::verifyAuditLog);
    safetyButtons->addWidget(backupButton);
    safetyButtons->addWidget(verifyBackupButton);
    safetyButtons->addWidget(verifyAuditButton);
    safetyButtons->addStretch();
    root->addLayout(safetyButtons);

    m_vaultStatus = new QLabel(QStringLiteral("未打开密钥库"));
    m_vaultStatus->setWordWrap(true);
    ui::setStatus(m_vaultStatus,
                  QStringLiteral("密钥库未打开。签发和配置导出操作暂不可用。"), "info");
    root->addWidget(m_vaultStatus);
    m_autoLockLabel = ui::label(QStringLiteral("自动锁定计时将在密钥库打开后启动。"),
                                "countdown");
    root->addWidget(m_autoLockLabel);
    QLabel *warning = new QLabel(QStringLiteral(
        "签名私钥只保存在加密密钥库。运行端配置包含根公钥和产品解密密钥，"
        "必须编译进目标应用，不能替代数字签名。"));
    warning->setWordWrap(true);
    warning->setProperty("role", "warning");
    root->addWidget(warning);
    root->addStretch();
    return page;
}

QWidget *MainWindow::createIssuePage()
{
    QScrollArea *page = new QScrollArea;
    page->setWidgetResizable(true);
    page->setFrameShape(QFrame::NoFrame);
    QWidget *content = new QWidget;
    content->setObjectName(QStringLiteral("AppShell"));
    QVBoxLayout *root = new QVBoxLayout(content);
    root->setContentsMargins(18, 20, 18, 18);
    root->setSpacing(15);
    ui::addPageHeader(root, QStringLiteral("单个授权"),
                      QStringLiteral("签发单个授权"),
                      QStringLiteral("填写客户与授权范围，导入设备请求，并在生成后立即执行自验证。"));

    QGroupBox *licenseBox = new QGroupBox(QStringLiteral("授权属性"));
    QFormLayout *form = new QFormLayout(licenseBox);
    form->setHorizontalSpacing(16);
    form->setVerticalSpacing(9);
    m_customerId = new QLineEdit;
    m_customerName = new QLineEdit;
    m_orderId = new QLineEdit;
    m_licenseMode = new QComboBox;
    m_targetRuntimeVersion = new QComboBox;
    m_targetRuntimeVersion->addItem(
                QStringLiteral("Runtime SDK 1.x（授权格式 v1）"), QStringLiteral("1.x"));
    m_targetRuntimeVersion->setToolTip(QStringLiteral(
        "签发前按目标应用集成的 Runtime SDK 系列检查授权格式兼容性。"));
    m_targetRuntimeVersion->setObjectName(QStringLiteral("targetRuntimeVersion"));
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
    expiryZone->setProperty("role", "helper");
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
    notBeforeZone->setProperty("role", "helper");
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
    runtimeSummary->setProperty("role", "helper");
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
    form->addRow(QStringLiteral("目标运行端版本"), m_targetRuntimeVersion);
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
    m_minimum->setEnabled(false);
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
    m_hardwareTable->setAlternatingRowColors(true);
    m_hardwareTable->setShowGrid(false);
    m_hardwareTable->verticalHeader()->setVisible(false);
    m_hardwareTable->setAccessibleName(QStringLiteral("授权硬件绑定列表"));
    m_hardwareTable->setToolTip(QStringLiteral(
        "悬浮硬件项目或识别方式可查看专业字段名。硬件值也可填写采集器生成的 SHA-256 匿名指纹。"));
    hardwareLayout->addWidget(m_hardwareTable);
    QHBoxLayout *hardwareButtons = new QHBoxLayout;
    QPushButton *collectButton = new QPushButton(QStringLiteral("采集本机"));
    QPushButton *addButton = new QPushButton(QStringLiteral("添加硬件项"));
    QPushButton *importButton = new QPushButton(QStringLiteral("导入硬件请求"));
    ui::setButtonRole(importButton, "primary");
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

    m_issueValidation = new QLabel;
    m_issueValidation->setObjectName(QStringLiteral("issueValidation"));
    m_issueValidation->setWordWrap(true);
    ui::setStatus(m_issueValidation,
                  QStringLiteral("请补充输出路径和至少一个有效硬件绑定项。"), "info");
    root->addWidget(m_issueValidation);
    m_licenseOutput = new QLineEdit;
    m_licenseOutput->setObjectName(QStringLiteral("licenseOutput"));
    m_licenseOutput->setPlaceholderText(QStringLiteral("授权文件保存位置"));
    root->addWidget(pathRow(m_licenseOutput, QStringLiteral("选择输出"),
                            this, SLOT(browseLicenseOutput())));
    m_issueButton = new QPushButton(QStringLiteral("检查并签发授权"));
    m_issueButton->setObjectName(QStringLiteral("issueLicenseButton"));
    ui::setButtonRole(m_issueButton, "accent");
    m_issueButton->setMinimumWidth(220);
    connect(m_issueButton, &QPushButton::clicked, this, &MainWindow::issueLicense);
    root->addWidget(m_issueButton, 0, Qt::AlignRight);

    connect(m_expiry, &QDateTimeEdit::dateTimeChanged,
            this, [this](const QDateTime &) { validateIssueForm(); });
    connect(m_notBefore, &QDateTimeEdit::dateTimeChanged,
            this, [this](const QDateTime &) { validateIssueForm(); });
    connect(m_runtimePreset, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) { validateIssueForm(); });
    connect(m_runtimeSeconds, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this](int) { validateIssueForm(); });
    connect(m_targetRuntimeVersion, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) { validateIssueForm(); });
    connect(m_licenseOutput, &QLineEdit::textChanged,
            this, [this](const QString &) { validateIssueForm(); });
    connect(m_minimum, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this](int) { validateIssueForm(); });
    connect(m_bindingMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int) {
        m_minimum->setEnabled(m_bindingMode->currentData().toString()
                              == QLatin1String("threshold"));
        validateIssueForm();
    });
    connect(m_hardwareTable, &QTableWidget::itemChanged,
            this, [this](QTableWidgetItem *) { validateIssueForm(); });
    page->setWidget(content);
    return page;
}

QWidget *MainWindow::createBatchPage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);
    root->setContentsMargins(18, 20, 18, 18);
    root->setSpacing(15);
    ui::addPageHeader(root, QStringLiteral("批量任务"),
                      QStringLiteral("批量签发授权"),
                      QStringLiteral("先预检整批数据，再一次性生成和发布；任一条失败时不留下半成品。"));
    QGroupBox *batchBox = new QGroupBox(QStringLiteral("批量任务"));
    QFormLayout *form = new QFormLayout(batchBox);
    form->setHorizontalSpacing(16);
    form->setVerticalSpacing(10);
    m_batchInput = new QLineEdit;
    m_batchOutput = new QLineEdit;
    m_batchInput->setToolTip(QStringLiteral("支持 CSV 或 JSON 格式的批量授权数据"));
    form->addRow(QStringLiteral("批量数据文件"),
                  pathRow(m_batchInput, QStringLiteral("选择"), this, SLOT(browseBatchInput())));
    form->addRow(QStringLiteral("授权文件输出目录"),
                  pathRow(m_batchOutput, QStringLiteral("选择"), this, SLOT(browseBatchOutput())));
    root->addWidget(batchBox);
    m_batchIssueButton = new QPushButton(QStringLiteral("预检、批量生成并原子发布"));
    m_batchIssueButton->setObjectName(QStringLiteral("batchIssueButton"));
    ui::setButtonRole(m_batchIssueButton, "accent");
    m_batchIssueButton->setMinimumWidth(250);
    connect(m_batchIssueButton, &QPushButton::clicked, this, &MainWindow::issueBatch);
    root->addWidget(m_batchIssueButton, 0, Qt::AlignRight);
    m_batchResult = new QTextEdit;
    m_batchResult->setReadOnly(true);
    m_batchResult->setPlaceholderText(QStringLiteral("批量任务的预检和签发结果将显示在这里。"));
    root->addWidget(m_batchResult, 1);
    return page;
}

QWidget *MainWindow::createInspectPage()
{
    QWidget *page = new QWidget;
    QVBoxLayout *root = new QVBoxLayout(page);
    root->setContentsMargins(18, 20, 18, 18);
    root->setSpacing(15);
    ui::addPageHeader(root, QStringLiteral("授权核验"),
                      QStringLiteral("读取并核验授权"),
                      QStringLiteral("查看客户授权的人类可读概览；需要排障时再打开完整技术数据。"));
    m_inspectPath = new QLineEdit;
    root->addWidget(pathRow(m_inspectPath, QStringLiteral("选择授权"),
                            this, SLOT(browseInspectLicense())));
    m_fullLocalCheck = new QCheckBox(QStringLiteral(
        "同时校验此电脑的硬件、有效期与离线防回拨状态（读取客户授权时通常不勾选）"));
    root->addWidget(m_fullLocalCheck);
    QPushButton *button = new QPushButton(QStringLiteral("验签、解密并读取"));
    ui::setButtonRole(button, "primary");
    button->setMinimumWidth(190);
    connect(button, &QPushButton::clicked, this, &MainWindow::inspectLicense);
    root->addWidget(button, 0, Qt::AlignRight);
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
        appendAudit(QStringLiteral("create_vault"), QStringLiteral("rejected"),
                    QString(), QString(), QStringLiteral("未选择保存路径"));
        return;
    }
    if (QFileInfo::exists(vaultPath)) {
        setVaultStatus(QStringLiteral(
                           "该路径已存在文件。若它是已创建的密钥库，请使用“打开密钥库”；否则请选择新文件名。"),
                       true);
        appendAudit(QStringLiteral("create_vault"), QStringLiteral("rejected"),
                    QString(), QString(), QStringLiteral("目标路径已存在"));
        return;
    }
    if (passwordCharacters < 10) {
        setVaultStatus(QStringLiteral("口令当前为 %1 个字符，至少需要 10 个字符。")
                       .arg(passwordCharacters), true);
        appendAudit(QStringLiteral("create_vault"), QStringLiteral("rejected"),
                    QString(), QString(), QStringLiteral("口令长度不足"));
        return;
    }
    if (!QRegularExpression(QStringLiteral("^[A-Za-z0-9._-]{1,128}$"))
            .match(productId).hasMatch()) {
        setVaultStatus(QStringLiteral(
                           "产品标识必须为 1–128 个英文字符，仅允许字母、数字、点、下划线和连字符。"),
                       true);
        appendAudit(QStringLiteral("create_vault"), QStringLiteral("rejected"),
                    QString(), QString(), QStringLiteral("产品标识格式无效"));
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
        appendAudit(QStringLiteral("create_vault"), QStringLiteral("failed"),
                    QString(), QString(), error);
        return;
    }
    QString status = QStringLiteral("已创建并打开。签名密钥标识：%1；产品密钥标识：%2")
            .arg(m_keys.keyId, m_keys.encryptionKeyId);
    if (!m_keys.secretsMemoryLocked) {
        status += QStringLiteral("\n警告：操作系统拒绝锁定敏感内存；密钥库可正常使用，但应关闭交换文件并限制签发机访问。");
    }
    setVaultStatus(status, !m_keys.secretsMemoryLocked);
    m_productId->setReadOnly(true);
    startAutoLockCountdown();
    updateVaultControls();
    appendAudit(QStringLiteral("create_vault"), QStringLiteral("success"),
                m_keys.keyId, vaultPath, QStringLiteral("已创建加密密钥库"));
    if (QMessageBox::question(
                this, QStringLiteral("立即备份密钥库"),
                QStringLiteral("密钥库已创建。是否现在复制一份加密备份？\n"
                               "建议保存到与签发机分离的受控离线介质。"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes) == QMessageBox::Yes) {
        backupVault();
    }
}

void MainWindow::openVault()
{
    if (!QFileInfo(m_vaultPath->text().trimmed()).isFile()) browseExistingVault();
    if (!QFileInfo(m_vaultPath->text().trimmed()).isFile()) {
        setVaultStatus(QStringLiteral("请选择一个现有的密钥库文件。"), true);
        appendAudit(QStringLiteral("open_vault"), QStringLiteral("rejected"),
                    QString(), QString(), QStringLiteral("未选择有效密钥库文件"));
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
        appendAudit(QStringLiteral("open_vault"), QStringLiteral("failed"),
                    QString(), QString(), error);
        return;
    }
    m_productId->setText(m_keys.productId);
    QString status = QStringLiteral("已打开。签名密钥标识：%1；产品密钥标识：%2")
            .arg(m_keys.keyId, m_keys.encryptionKeyId);
    if (!m_keys.secretsMemoryLocked) {
        status += QStringLiteral("\n警告：操作系统拒绝锁定敏感内存；密钥库可正常使用，但应关闭交换文件并限制签发机访问。");
    }
    setVaultStatus(status, !m_keys.secretsMemoryLocked);
    m_productId->setReadOnly(true);
    startAutoLockCountdown();
    updateVaultControls();
    appendAudit(QStringLiteral("open_vault"), QStringLiteral("success"),
                m_keys.keyId, m_vaultPath->text(), QStringLiteral("密钥库已解锁"));
}

void MainWindow::lockVault()
{
    const bool wasOpen = m_keys.isComplete();
    const QString productId = m_keys.productId;
    const QString keyId = m_keys.keyId;
    m_keys.clearSecrets();
    m_vaultPassword->clear();
    if (m_autoLockTimer) m_autoLockTimer->stop();
    if (m_lockCountdownTimer) m_lockCountdownTimer->stop();
    m_productId->setReadOnly(false);
    if (m_autoLockLabel) {
        m_autoLockLabel->setText(QStringLiteral("当前已锁定；敏感密钥已从活动内存清零。"));
        m_autoLockLabel->setProperty("state", "normal");
        m_autoLockLabel->style()->unpolish(m_autoLockLabel);
        m_autoLockLabel->style()->polish(m_autoLockLabel);
    }
    ui::setStatus(m_vaultStatus,
                  QStringLiteral("密钥库已锁定；私钥和产品密钥已从活动内存清零。"),
                  "info");
    updateVaultControls();
    if (wasOpen) {
        AuditEvent event;
        event.action = QStringLiteral("lock_vault");
        event.outcome = QStringLiteral("success");
        event.productId = productId;
        event.subjectId = keyId;
        event.message = QStringLiteral("密钥材料已清零");
        QString auditError;
        if (!AuditLogger::append(event, QString(), &auditError)) {
            statusBar()->showMessage(QStringLiteral("审计日志写入失败：") + auditError, 10000);
        }
    }
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
        appendAudit(QStringLiteral("export_runtime"), QStringLiteral("failed"),
                    m_keys.encryptionKeyId, QString(), error);
        QMessageBox::critical(this, QStringLiteral("导出失败"), error);
        return;
    }
    appendAudit(QStringLiteral("export_runtime"), QStringLiteral("success"),
                m_keys.encryptionKeyId, path, QStringLiteral("已导出运行端配置"));
    QMessageBox::information(this, QStringLiteral("导出完成"),
                             QStringLiteral("已生成：\n%1\n%2").arg(path, headerPath));
}

void MainWindow::backupVault()
{
    const QString sourcePath = m_vaultPath->text().trimmed();
    if (!QFileInfo(sourcePath).isFile()) {
        QMessageBox::warning(this, QStringLiteral("无法备份"),
                             QStringLiteral("请先选择或创建有效的密钥库文件。"));
        return;
    }
    const QString defaultName = QFileInfo(sourcePath).completeBaseName()
            + QStringLiteral("-backup.qtkv");
    const QString destination = QFileDialog::getSaveFileName(
                this, QStringLiteral("复制加密密钥库备份"), defaultName,
                QStringLiteral("密钥库文件 (*.qtkv)"));
    if (destination.isEmpty()) return;
    if (QFileInfo::exists(destination)) {
        QMessageBox::warning(this, QStringLiteral("无法备份"),
                             QStringLiteral("目标文件已存在。为避免覆盖，请选择新文件名。"));
        appendAudit(QStringLiteral("backup_vault"), QStringLiteral("rejected"),
                    m_keys.keyId, QString(), QStringLiteral("备份目标已存在"));
        return;
    }
    if (!QFile::copy(sourcePath, destination)) {
        appendAudit(QStringLiteral("backup_vault"), QStringLiteral("failed"),
                    m_keys.keyId, QString(), QStringLiteral("复制失败"));
        QMessageBox::critical(this, QStringLiteral("备份失败"),
                              QStringLiteral("无法复制密钥库到目标位置。"));
        return;
    }
    QString hashError;
    const QString sourceHash = AuditLogger::fileSha256(sourcePath, &hashError);
    const QString backupHash = AuditLogger::fileSha256(destination, &hashError);
    if (sourceHash.isEmpty() || sourceHash != backupHash) {
        QFile::remove(destination);
        appendAudit(QStringLiteral("backup_vault"), QStringLiteral("failed"),
                    m_keys.keyId, QString(), QStringLiteral("复制后哈希不一致"));
        QMessageBox::critical(this, QStringLiteral("备份失败"),
                              QStringLiteral("复制后的文件哈希不一致，已删除不完整备份。"));
        return;
    }
    appendAudit(QStringLiteral("backup_vault"), QStringLiteral("success"),
                m_keys.keyId, destination, QStringLiteral("加密备份复制并校验哈希成功"));
    QMessageBox::information(
                this, QStringLiteral("备份完成"),
                QStringLiteral("加密密钥库已复制并完成 SHA-256 校验。\n\n"
                               "请继续使用“验证备份可恢复”执行口令和产品一致性检查。\n"
                               "SHA-256：%1").arg(backupHash));
}

void MainWindow::verifyVaultBackup()
{
    const QString path = QFileDialog::getOpenFileName(
                this, QStringLiteral("选择要验证的密钥库备份"), QString(),
                QStringLiteral("密钥库文件 (*.qtkv)"));
    if (path.isEmpty()) return;
    bool accepted = false;
    const QString passwordText = QInputDialog::getText(
                this, QStringLiteral("验证备份口令"),
                QStringLiteral("输入该备份的密钥库口令。口令只在内存中用于本次验证。"),
                QLineEdit::Password, QString(), &accepted);
    if (!accepted) return;
    QByteArray password = passwordText.toUtf8();
    KeyVaultMaterial backup;
    QString error;
    const bool opened = KeyVault::open(path, password, &backup, &error);
    CryptoProvider::wipe(password);
    if (!opened) {
        appendAudit(QStringLiteral("verify_vault_backup"), QStringLiteral("failed"),
                    QString(), path, error);
        QMessageBox::critical(this, QStringLiteral("备份不可恢复"), error);
        return;
    }
    const bool matchesOpenVault = !m_keys.isComplete()
            || (backup.productId == m_keys.productId
                && backup.keyId == m_keys.keyId
                && backup.encryptionKeyId == m_keys.encryptionKeyId
                && backup.rootPublicKey == m_keys.rootPublicKey);
    const QString productId = backup.productId;
    const QString keyId = backup.keyId;
    backup.clearSecrets();
    if (!matchesOpenVault) {
        appendAudit(QStringLiteral("verify_vault_backup"), QStringLiteral("rejected"),
                    keyId, path, QStringLiteral("与当前打开的密钥库不一致"));
        QMessageBox::critical(this, QStringLiteral("备份不匹配"),
                              QStringLiteral("备份可以打开，但与当前密钥库的产品或密钥标识不一致。"));
        return;
    }
    appendAudit(QStringLiteral("verify_vault_backup"), QStringLiteral("success"),
                keyId, path, QStringLiteral("备份可打开且标识一致"));
    QMessageBox::information(this, QStringLiteral("备份可恢复"),
                             QStringLiteral("备份已成功解密并验证。\n产品标识：%1\n签名密钥标识：%2")
                             .arg(productId, keyId));
}

void MainWindow::verifyAuditLog()
{
    const QString path = QFileDialog::getOpenFileName(
                this, QStringLiteral("选择审计日志"), AuditLogger::defaultLogPath(),
                QStringLiteral("审计日志 (*.jsonl);;所有文件 (*)"));
    if (path.isEmpty()) return;
    int count = 0;
    QString error;
    if (!AuditLogger::verify(path, &count, &error)) {
        QMessageBox::critical(this, QStringLiteral("审计日志校验失败"), error);
        return;
    }
    QMessageBox::information(this, QStringLiteral("审计日志有效"),
                             QStringLiteral("哈希链完整，共 %1 条记录。" ).arg(count));
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
        appendAudit(QStringLiteral("import_hardware_request"), QStringLiteral("failed"),
                    QString(), QString(), QStringLiteral("无法读取文件"));
        QMessageBox::critical(this, QStringLiteral("导入失败"), QStringLiteral("无法读取文件"));
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    QString product;
    QVector<HardwareValue> values;
    QString error;
    if (parseError.error != QJsonParseError::NoError || !document.isObject()
            || !HardwareFingerprint::requestFromJson(document.object(), &product, &values, &error)) {
        appendAudit(QStringLiteral("import_hardware_request"), QStringLiteral("failed"),
                    QString(), path, error.isEmpty() ? parseError.errorString() : error);
        QMessageBox::critical(this, QStringLiteral("导入失败"),
                              error.isEmpty() ? parseError.errorString() : error);
        return;
    }
    if (m_keys.isComplete() && product != m_keys.productId) {
        appendAudit(QStringLiteral("import_hardware_request"), QStringLiteral("rejected"),
                    QString(), path, QStringLiteral("硬件请求产品不匹配"));
        QMessageBox::critical(this, QStringLiteral("导入失败"), QStringLiteral("硬件请求产品不匹配"));
        return;
    }
    for (const HardwareValue &value : values) appendHardware(value);
    appendAudit(QStringLiteral("import_hardware_request"), QStringLiteral("success"),
                QString(), path, QStringLiteral("导入硬件项目=%1").arg(values.size()));
}

void MainWindow::browseLicenseOutput()
{
    const QString path = QFileDialog::getSaveFileName(
                this, QStringLiteral("授权输出"), QStringLiteral("license.qtlic"),
                QStringLiteral("授权文件 (*.qtlic)"));
    if (!path.isEmpty()) m_licenseOutput->setText(path);
}

bool MainWindow::buildCurrentPayload(LicensePayload *payload, QString *error) const
{
    if (!payload) {
        if (error) *error = QStringLiteral("授权载荷输出参数无效");
        return false;
    }
    const QVector<HardwareValue> hardware = selectedHardware(error);
    if (hardware.isEmpty()) return false;

    LicensePayload result;
    result.licenseId = QStringLiteral("preview-license");
    result.productId = m_keys.isComplete() ? m_keys.productId : m_productId->text().trimmed();
    if (result.productId.isEmpty()) result.productId = QStringLiteral("preview-product");
    result.customerId = m_customerId->text().trimmed();
    result.customerName = m_customerName->text().trimmed();
    result.orderId = m_orderId->text().trimmed();
    result.issuedAt = QDateTime::currentSecsSinceEpoch();
    if (!licenseModeFromString(m_licenseMode->currentData().toString(),
                               &result.licenseMode)) {
        if (error) *error = QStringLiteral("授权模式无效");
        return false;
    }
    if (result.licenseMode == LicenseMode::FixedExpiry
            || result.licenseMode == LicenseMode::Hybrid) {
        result.expiresAt = m_expiry->dateTime().toUTC().toSecsSinceEpoch();
    }
    if (m_notBeforeEnabled->isChecked()) {
        result.notBefore = m_notBefore->dateTime().toUTC().toSecsSinceEpoch();
    }
    if (result.licenseMode == LicenseMode::ValidityDuration
            || result.licenseMode == LicenseMode::RuntimeQuota
            || result.licenseMode == LicenseMode::Hybrid) {
        result.maxRuntimeSeconds = m_runtimeSeconds->value();
    }
    result.features = m_features->text().split(
                QRegularExpression(QStringLiteral("[,;|\\s]+")), QString::SkipEmptyParts);
    result.features.removeDuplicates();
    result.features.sort();
    result.issuer = QStringLiteral("QtLicenseIssuer");
    result.note = m_note->text().trimmed();
    result.binding = HardwareFingerprint::bindingFromValues(
                hardware, m_bindingMode->currentData().toString(),
                m_minimum->value(), error);
    if (!validateLicensePayload(result, error)) return false;
    *payload = result;
    return true;
}

bool MainWindow::validateIssueForm(bool focusFirstInvalid)
{
    if (!m_issueValidation || !m_issueButton || !m_licenseOutput
            || !m_hardwareTable || !m_targetRuntimeVersion) {
        return false;
    }
    setInvalid(m_licenseOutput, false);
    setInvalid(m_hardwareTable, false);
    setInvalid(m_expiry, false);
    setInvalid(m_notBefore, false);
    setInvalid(m_targetRuntimeVersion, false);
    setInvalid(m_licenseMode, false);

    QStringList issues;
    QWidget *firstInvalid = nullptr;
    const auto addIssue = [&issues, &firstInvalid](QWidget *widget, const QString &message) {
        issues.append(message);
        setInvalid(widget, true);
        if (!firstInvalid) firstInvalid = widget;
    };

    const QString outputPath = m_licenseOutput->text().trimmed();
    if (outputPath.isEmpty()) {
        addIssue(m_licenseOutput, QStringLiteral("请选择授权文件输出位置。"));
    } else if (QFileInfo::exists(outputPath)) {
        addIssue(m_licenseOutput, QStringLiteral("输出文件已存在；为避免覆盖，请选择新文件名。"));
    } else if (!QFileInfo(outputPath).absoluteDir().exists()) {
        addIssue(m_licenseOutput, QStringLiteral("输出目录不存在。"));
    }

    LicenseMode mode;
    if (!licenseModeFromString(m_licenseMode->currentData().toString(), &mode)) {
        addIssue(m_licenseMode, QStringLiteral("授权模式无效。"));
    } else {
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const qint64 expiry = m_expiry->dateTime().toUTC().toSecsSinceEpoch();
        const qint64 notBefore = m_notBefore->dateTime().toUTC().toSecsSinceEpoch();
        if ((mode == LicenseMode::FixedExpiry || mode == LicenseMode::Hybrid)
                && expiry <= now) {
            addIssue(m_expiry, QStringLiteral("到期时间必须晚于当前时间。"));
        }
        if (m_notBeforeEnabled->isChecked()
                && (mode == LicenseMode::FixedExpiry || mode == LicenseMode::Hybrid)
                && notBefore >= expiry) {
            addIssue(m_notBefore, QStringLiteral("生效时间必须早于到期时间。"));
        }
        if (m_notBeforeEnabled->isChecked() && mode == LicenseMode::ValidityDuration
                && notBefore >= now + m_runtimeSeconds->value()) {
            addIssue(m_notBefore, QStringLiteral("生效时间必须早于签发后有效时长的截止时间。"));
        }
    }

    LicensePayload payload;
    QString payloadError;
    if (!buildCurrentPayload(&payload, &payloadError)) {
        addIssue(m_hardwareTable,
                 payloadError.isEmpty() ? QStringLiteral("硬件绑定信息无效。") : payloadError);
    } else {
        const RuntimeCompatibilityResult compatibility = RuntimeCompatibility::check(
                    m_targetRuntimeVersion->currentData().toString(), payload);
        if (!compatibility.compatible) {
            addIssue(m_targetRuntimeVersion, compatibility.message);
        }
    }

    const bool valid = issues.isEmpty();
    if (valid) {
        ui::setStatus(
                    m_issueValidation,
                    m_keys.isComplete()
                    ? QStringLiteral("配置完整且兼容目标运行端，可以进入签发确认。")
                    : QStringLiteral("配置完整；打开密钥库后即可签发。"),
                    m_keys.isComplete() ? "success" : "info");
    } else {
        ui::setStatus(m_issueValidation,
                      QStringLiteral("请修正以下问题：\n• ")
                      + issues.join(QStringLiteral("\n• ")), "error");
    }
    m_issueButton->setEnabled(valid && m_keys.isComplete());
    if (focusFirstInvalid && firstInvalid) firstInvalid->setFocus(Qt::OtherFocusReason);
    return valid;
}

void MainWindow::issueLicense()
{
    if (!validateIssueForm(true) || !requireOpenVault()) return;
    QString error;
    LicensePayload payload;
    if (!buildCurrentPayload(&payload, &error)) {
        appendAudit(QStringLiteral("issue_license"), QStringLiteral("rejected"),
                    QString(), QString(), error);
        QMessageBox::critical(this, QStringLiteral("生成失败"), error);
        return;
    }
    payload.licenseId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    payload.issuedAt = QDateTime::currentSecsSinceEpoch();
    if (!validateLicensePayload(payload, &error)) {
        appendAudit(QStringLiteral("issue_license"), QStringLiteral("rejected"),
                    payload.licenseId, QString(), error);
        QMessageBox::critical(this, QStringLiteral("生成失败"), error);
        return;
    }
    const RuntimeCompatibilityResult compatibility = RuntimeCompatibility::check(
                m_targetRuntimeVersion->currentData().toString(), payload);
    if (!compatibility.compatible) {
        appendAudit(QStringLiteral("issue_license"), QStringLiteral("rejected"),
                    payload.licenseId, QString(), compatibility.message);
        QMessageBox::critical(this, QStringLiteral("运行端不兼容"), compatibility.message);
        return;
    }
    const QStringList confirmationLines = QStringList()
            << QStringLiteral("产品：%1").arg(payload.productId)
            << QStringLiteral("客户：%1 / %2")
               .arg(displayText(payload.customerId), displayText(payload.customerName))
            << QStringLiteral("授权模式：%1").arg(m_licenseMode->currentText())
            << QStringLiteral("授权功能：%1")
               .arg(payload.features.isEmpty() ? QStringLiteral("未限制功能项")
                                               : payload.features.join(QStringLiteral("、")))
            << QStringLiteral("硬件规则：%1，%2 个绑定项目")
               .arg(m_bindingMode->currentText())
               .arg(payload.binding.bindingSlots.size())
            << QStringLiteral("目标运行端：%1").arg(m_targetRuntimeVersion->currentText())
            << QStringLiteral("输出文件：%1").arg(m_licenseOutput->text());
    QMessageBox confirmation(QMessageBox::Question, QStringLiteral("确认签发授权"),
                             QStringLiteral("请确认以下信息。签发后不会覆盖已有文件。"),
                             QMessageBox::Yes | QMessageBox::Cancel, this);
    confirmation.setInformativeText(confirmationLines.join(QLatin1Char('\n')));
    confirmation.button(QMessageBox::Yes)->setText(QStringLiteral("确认签发"));
    confirmation.button(QMessageBox::Cancel)->setText(QStringLiteral("返回修改"));
    confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) {
        appendAudit(QStringLiteral("issue_license"), QStringLiteral("cancelled"),
                    payload.licenseId, QString(), QStringLiteral("用户在确认摘要取消"));
        return;
    }
    if (!LicenseCodec::issueToFile(payload, m_keys, m_licenseOutput->text(), &error)) {
        appendAudit(QStringLiteral("issue_license"), QStringLiteral("failed"),
                    payload.licenseId, QString(), error);
        QMessageBox::critical(this, QStringLiteral("生成失败"), error);
        return;
    }
    appendAudit(QStringLiteral("issue_license"), QStringLiteral("success"),
                payload.licenseId, m_licenseOutput->text(),
                QStringLiteral("客户编号=%1；运行端最低版本=%2")
                .arg(displayText(payload.customerId), compatibility.minimumVersion));
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
    validateIssueForm();
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
    validateIssueForm();
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
    const QString inputPath = m_batchInput->text().trimmed();
    const QString outputPath = m_batchOutput->text().trimmed();
    if (!QFileInfo(inputPath).isFile() || outputPath.isEmpty()
            || QFileInfo::exists(outputPath)) {
        const QString message = QStringLiteral(
                    "请选择有效的批量数据文件，并使用尚不存在的输出目录。" );
        m_batchResult->setPlainText(QStringLiteral("预检失败：") + message);
        appendAudit(QStringLiteral("issue_batch"), QStringLiteral("rejected"),
                    QString(), QString(), message);
        return;
    }
    LicensePayload preview;
    const RuntimeCompatibilityResult compatibility = RuntimeCompatibility::check(
                QStringLiteral("1.x"), preview);
    if (!compatibility.compatible) {
        m_batchResult->setPlainText(QStringLiteral("预检失败：") + compatibility.message);
        return;
    }
    QMessageBox confirmation(QMessageBox::Question, QStringLiteral("确认批量签发"),
                             QStringLiteral("将先预检全部记录，再原子发布整个批次。"),
                             QMessageBox::Yes | QMessageBox::Cancel, this);
    confirmation.setInformativeText(
                QStringLiteral("输入文件：%1\n输出目录：%2\n目标运行端：Runtime SDK 1.x")
                .arg(inputPath, outputPath));
    confirmation.button(QMessageBox::Yes)->setText(QStringLiteral("确认批量签发"));
    confirmation.button(QMessageBox::Cancel)->setText(QStringLiteral("返回修改"));
    confirmation.setDefaultButton(QMessageBox::Cancel);
    if (confirmation.exec() != QMessageBox::Yes) {
        appendAudit(QStringLiteral("issue_batch"), QStringLiteral("cancelled"));
        return;
    }
    BatchIssueResult result;
    QString error;
    if (!BatchIssuer::issueFile(inputPath, outputPath,
                                m_keys, &result, &error)) {
        m_batchResult->setPlainText(QStringLiteral("失败：") + error);
        appendAudit(QStringLiteral("issue_batch"), QStringLiteral("failed"),
                    QString(), QString(), error);
        return;
    }
    appendAudit(QStringLiteral("issue_batch"), QStringLiteral("success"),
                result.batchId,
                QDir(result.outputDirectory).filePath(QStringLiteral("batch-manifest.json")),
                QStringLiteral("生成数量=%1；运行端最低版本=%2")
                .arg(result.issuedCount).arg(compatibility.minimumVersion));
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
    appendAudit(QStringLiteral("inspect_license"),
                decision.valid() ? QStringLiteral("success") : QStringLiteral("failed"),
                decision.payload.licenseId, m_inspectPath->text(), decision.message);
}

void MainWindow::showFirstRunWizard()
{
    QWizard wizard(this);
    wizard.setWindowTitle(QStringLiteral("离线授权首次使用向导"));
    wizard.setWizardStyle(QWizard::ModernStyle);
    wizard.setMinimumSize(680, 460);
    wizard.setOption(QWizard::HaveCustomButton1, true);
    wizard.setButtonText(QWizard::CustomButton1, QStringLiteral("不再自动显示"));
    wizard.addPage(onboardingPage(
        QStringLiteral("1. 准备离线签发环境"),
        QStringLiteral("签发机应由授权管理员控制，并在断网环境中运行。"),
        QStringList()
            << QStringLiteral("确认系统时间和时区正确。")
            << QStringLiteral("准备两个独立的受控离线介质，用于密钥库备份和客户文件交换。")
            << QStringLiteral("不要把密钥库、口令或运行端解密配置上传到云端。")));
    wizard.addPage(onboardingPage(
        QStringLiteral("2. 创建并备份密钥库"),
        QStringLiteral("密钥库保存签名私钥和产品密钥，是签发能力的唯一根。"),
        QStringList()
            << QStringLiteral("在“密钥库”页填写产品标识和不少于 10 个字符的口令。")
            << QStringLiteral("创建后立即复制加密备份，并使用“验证备份可恢复”检查。")
            << QStringLiteral("口令不会写入磁盘，遗失后无法恢复密钥库。")));
    wizard.addPage(onboardingPage(
        QStringLiteral("3. 集成目标应用"),
        QStringLiteral("签发前先把运行端配置与 Runtime SDK 编译进目标应用。"),
        QStringList()
            << QStringLiteral("导出 runtime-config.json 与 qtlicense_runtime_config.h。")
            << QStringLiteral("生产应用使用头文件版本，并删除中间 JSON 文件。")
            << QStringLiteral("确认目标应用使用 Runtime SDK 1.x。")));
    wizard.addPage(onboardingPage(
        QStringLiteral("4. 采集、确认并签发"),
        QStringLiteral("客户机只提交匿名硬件指纹；签发端在最终确认后生成授权。"),
        QStringList()
            << QStringLiteral("客户运行采集器生成 .qreq 文件。")
            << QStringLiteral("导入请求，设置期限、功能和硬件策略。")
            << QStringLiteral("修正页面内提示的问题，核对确认摘要，再执行签发。")));
    connect(&wizard, &QWizard::customButtonClicked, &wizard,
            [&wizard](int button) {
        if (button != QWizard::CustomButton1) return;
        QSettings settings;
        settings.setValue(QStringLiteral("onboarding/completed"), true);
        settings.sync();
        wizard.reject();
    });
    if (wizard.exec() == QDialog::Accepted) {
        QSettings settings;
        settings.setValue(QStringLiteral("onboarding/completed"), true);
        settings.sync();
        if (m_tabs) m_tabs->setCurrentIndex(0);
    }
}

void MainWindow::startAutoLockCountdown()
{
    if (!m_keys.isComplete()) return;
    m_autoLockTimer->start();
    m_lockCountdownTimer->start();
    updateAutoLockCountdown();
}

void MainWindow::updateAutoLockCountdown()
{
    if (!m_autoLockLabel || !m_keys.isComplete() || !m_autoLockTimer->isActive()) return;
    const int remainingSeconds = qMax(0, (m_autoLockTimer->remainingTime() + 999) / 1000);
    const int minutes = remainingSeconds / 60;
    const int seconds = remainingSeconds % 60;
    m_autoLockLabel->setText(QStringLiteral("密钥库已解锁；无操作 %1:%2 后自动锁定。")
                             .arg(minutes, 2, 10, QLatin1Char('0'))
                             .arg(seconds, 2, 10, QLatin1Char('0')));
    m_autoLockLabel->setProperty("state", remainingSeconds <= 60 ? "warning" : "normal");
    m_autoLockLabel->style()->unpolish(m_autoLockLabel);
    m_autoLockLabel->style()->polish(m_autoLockLabel);
    m_autoLockLabel->update();
}

void MainWindow::updateVaultControls()
{
    const bool open = m_keys.isComplete();
    if (m_exportRuntimeButton) m_exportRuntimeButton->setEnabled(open);
    if (m_batchIssueButton) m_batchIssueButton->setEnabled(open);
    if (m_productId) m_productId->setReadOnly(open);
    validateIssueForm();
}

void MainWindow::appendAudit(const QString &action, const QString &outcome,
                             const QString &subjectId, const QString &filePath,
                             const QString &message)
{
    AuditEvent event;
    event.action = action;
    event.outcome = outcome;
    event.productId = m_keys.isComplete() ? m_keys.productId : m_productId->text().trimmed();
    event.subjectId = subjectId;
    event.filePath = QFileInfo(filePath).isFile() ? filePath : QString();
    event.message = message;
    QString error;
    if (!AuditLogger::append(event, QString(), &error)) {
        statusBar()->showMessage(QStringLiteral("审计日志写入失败：") + error, 10000);
    }
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
        startAutoLockCountdown();
        return true;
    }
    QMessageBox::warning(this, QStringLiteral("未打开密钥库"),
                         QStringLiteral("请先创建或打开密钥库。"));
    return false;
}

void MainWindow::setVaultStatus(const QString &text, bool error)
{
    ui::setStatus(m_vaultStatus, text, error ? "error" : "success");
}
