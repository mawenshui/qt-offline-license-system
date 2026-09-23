#include <QApplication>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>

#include <cstdio>

#include "mainwindow.h"
#include "qt_license_theme.h"

namespace {

bool check(bool condition, const char *message)
{
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

} // namespace

int main(int argc, char *argv[])
{
    qputenv("QTLIC_SKIP_ONBOARDING", "1");
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("MyToolsProjectTests"));
    QApplication::setApplicationName(QStringLiteral("QtLicenseIssuerUiTests"));
    qtlic::ui::applyTheme(app);

    MainWindow window;
    window.show();
    app.processEvents();

    QTabWidget *tabs = window.findChild<QTabWidget *>(QStringLiteral("mainTabs"));
    QPushButton *exportButton = window.findChild<QPushButton *>(
                QStringLiteral("exportRuntimeButton"));
    QPushButton *issueButton = window.findChild<QPushButton *>(
                QStringLiteral("issueLicenseButton"));
    QPushButton *batchButton = window.findChild<QPushButton *>(
                QStringLiteral("batchIssueButton"));
    QComboBox *runtimeVersion = window.findChild<QComboBox *>(
                QStringLiteral("targetRuntimeVersion"));
    QLabel *validation = window.findChild<QLabel *>(QStringLiteral("issueValidation"));

    if (!check(tabs && tabs->count() == 4, "main workflow tabs missing")) return 1;
    if (!check(exportButton && !exportButton->isEnabled(),
               "runtime export must be gated while vault is locked")) return 1;
    if (!check(issueButton && !issueButton->isEnabled(),
               "single issue must be gated while form/vault is invalid")) return 1;
    if (!check(batchButton && !batchButton->isEnabled(),
               "batch issue must be gated while vault is locked")) return 1;
    if (!check(runtimeVersion
               && runtimeVersion->currentData().toString() == QLatin1String("1.x"),
               "runtime compatibility target missing")) return 1;
    if (!check(validation && validation->text().contains(QStringLiteral("修正")),
               "inline validation summary missing")) return 1;
    if (!check(app.styleSheet().contains(QStringLiteral("QLabel[role=\"status\"]")),
               "shared application theme missing")) return 1;

    window.close();
    std::fprintf(stdout, "Issuer UI smoke scenarios passed\n");
    return 0;
}
