#include "license_types.h"

#include <QCoreApplication>
#include <QString>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const qtlic::LicenseDecision decision;
    return decision.valid() || qtlic::licenseStatusToString(decision.status).isEmpty() ? 1 : 0;
}
