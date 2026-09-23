#ifndef QTLIC_MAINWINDOW_H
#define QTLIC_MAINWINDOW_H

#include <QMainWindow>

#include "license_types.h"

class QCheckBox;
class QComboBox;
class QDateTimeEdit;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QTextEdit;
class QTimer;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void browseNewVault();
    void browseExistingVault();
    void createVault();
    void openVault();
    void lockVault();
    void exportRuntimeConfig();
    void backupVault();
    void verifyVaultBackup();
    void verifyAuditLog();
    void collectHardware();
    void addHardwareRow();
    void importHardwareRequest();
    void browseLicenseOutput();
    void issueLicense();
    void updateModeControls();
    void browseBatchInput();
    void browseBatchOutput();
    void issueBatch();
    void browseInspectLicense();
    void inspectLicense();

private:
    QWidget *createVaultPage();
    QWidget *createIssuePage();
    QWidget *createBatchPage();
    QWidget *createInspectPage();
    void showFirstRunWizard();
    void startAutoLockCountdown();
    void updateAutoLockCountdown();
    void updateVaultControls();
    bool buildCurrentPayload(qtlic::LicensePayload *payload, QString *error) const;
    bool validateIssueForm(bool focusFirstInvalid = false);
    void appendAudit(const QString &action, const QString &outcome,
                     const QString &subjectId = QString(),
                     const QString &filePath = QString(),
                     const QString &message = QString());
    QVector<qtlic::HardwareValue> selectedHardware(QString *error) const;
    void appendHardware(const qtlic::HardwareValue &value, bool selected = true);
    bool requireOpenVault();
    void setVaultStatus(const QString &text, bool error = false);

    qtlic::KeyVaultMaterial m_keys;

    QLineEdit *m_vaultPath = nullptr;
    QLineEdit *m_vaultPassword = nullptr;
    QLineEdit *m_productId = nullptr;
    QLabel *m_vaultStatus = nullptr;
    QLabel *m_autoLockLabel = nullptr;
    QTimer *m_autoLockTimer = nullptr;
    QTimer *m_lockCountdownTimer = nullptr;
    QTabWidget *m_tabs = nullptr;
    QPushButton *m_exportRuntimeButton = nullptr;

    QLineEdit *m_customerId = nullptr;
    QLineEdit *m_customerName = nullptr;
    QLineEdit *m_orderId = nullptr;
    QComboBox *m_licenseMode = nullptr;
    QComboBox *m_targetRuntimeVersion = nullptr;
    QCheckBox *m_notBeforeEnabled = nullptr;
    QDateTimeEdit *m_notBefore = nullptr;
    QDateTimeEdit *m_expiry = nullptr;
    QComboBox *m_runtimePreset = nullptr;
    QSpinBox *m_runtimeSeconds = nullptr;
    QLabel *m_runtimeLabel = nullptr;
    QLineEdit *m_features = nullptr;
    QLineEdit *m_note = nullptr;
    QComboBox *m_bindingMode = nullptr;
    QSpinBox *m_minimum = nullptr;
    QTableWidget *m_hardwareTable = nullptr;
    QLineEdit *m_licenseOutput = nullptr;
    QLabel *m_issueValidation = nullptr;
    QPushButton *m_issueButton = nullptr;

    QLineEdit *m_batchInput = nullptr;
    QLineEdit *m_batchOutput = nullptr;
    QTextEdit *m_batchResult = nullptr;
    QPushButton *m_batchIssueButton = nullptr;

    QLineEdit *m_inspectPath = nullptr;
    QCheckBox *m_fullLocalCheck = nullptr;
    QTextEdit *m_inspectResult = nullptr;
    QTextEdit *m_inspectRawJson = nullptr;
};

#endif
