#include "mainwindow.h"
#include "qt_license_theme.h"
#include "version.h"

#include <QApplication>
#include <QtGlobal>

int main(int argc, char *argv[])
{
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#endif
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("QtLicenseIssuer"));
    QApplication::setApplicationDisplayName(QStringLiteral("离线授权控制台"));
    QApplication::setApplicationVersion(QStringLiteral(QTLIC_VERSION_STR));
    QApplication::setOrganizationName(QStringLiteral("MyToolsProject"));
    qtlic::ui::applyTheme(app);

    MainWindow window;
    window.show();
    return app.exec();
}
