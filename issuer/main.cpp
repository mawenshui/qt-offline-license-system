#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("QtLicenseIssuer"));
    QApplication::setOrganizationName(QStringLiteral("MyToolsProject"));

    MainWindow window;
    window.show();
    return app.exec();
}
