TEMPLATE = subdirs

SUBDIRS += \
    license_core \
    collector_app \
    issuer_app \
    cli_app \
    tests_app

license_core.file = core/QtLicenseCore.pro
collector_app.file = collector/HardwareCollector.pro
issuer_app.file = issuer/LicenseIssuer.pro
cli_app.file = cli/LicenseCli.pro
tests_app.file = tests/LicenseCoreTests.pro

collector_app.depends = license_core
issuer_app.depends = license_core
cli_app.depends = license_core
tests_app.depends = license_core
