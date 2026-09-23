QT -= gui
QT += core

TEMPLATE = app
CONFIG += console c++14 warn_on
TARGET = qt-license-cli

LICENSESYSTEM_ROOT = $$clean_path($$PWD/..)
SODIUM_ROOT = $$LICENSESYSTEM_ROOT/third_party/libsodium
DESTDIR = $$LICENSESYSTEM_ROOT/bin
OBJECTS_DIR = $$OUT_PWD/obj

INCLUDEPATH += $$LICENSESYSTEM_ROOT/core
LIBS += -L$$LICENSESYSTEM_ROOT/bin/lib -lQtLicenseCore
PRE_TARGETDEPS += $$LICENSESYSTEM_ROOT/bin/lib/libQtLicenseCore.a
include($$LICENSESYSTEM_ROOT/third_party/libsodium/libsodium.pri)

SOURCES += main.cpp

win32: LIBS += -lcrypt32
