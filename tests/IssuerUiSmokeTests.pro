QT += core gui widgets

TEMPLATE = app
CONFIG += console c++14 warn_on
TARGET = issuer-ui-smoke-tests

LICENSESYSTEM_ROOT = $$clean_path($$PWD/..)
SODIUM_ROOT = $$LICENSESYSTEM_ROOT/third_party/libsodium
DESTDIR = $$LICENSESYSTEM_ROOT/bin
OBJECTS_DIR = $$OUT_PWD/obj
MOC_DIR = $$OUT_PWD/moc

INCLUDEPATH += \
    $$LICENSESYSTEM_ROOT/core \
    $$LICENSESYSTEM_ROOT/issuer \
    $$LICENSESYSTEM_ROOT/ui
LIBS += -L$$LICENSESYSTEM_ROOT/bin/lib -lQtLicenseCore
PRE_TARGETDEPS += $$LICENSESYSTEM_ROOT/bin/lib/libQtLicenseCore.a
include($$LICENSESYSTEM_ROOT/third_party/libsodium/libsodium.pri)

HEADERS += \
    $$LICENSESYSTEM_ROOT/issuer/mainwindow.h \
    $$LICENSESYSTEM_ROOT/ui/qt_license_theme.h
SOURCES += \
    issuer_ui_smoke.cpp \
    $$LICENSESYSTEM_ROOT/issuer/mainwindow.cpp

win32: LIBS += -lcrypt32
