QT -= gui
QT += core

TEMPLATE = app
CONFIG += console c++14 warn_on
TARGET = runtime-sdk-smoke
DESTDIR = $$OUT_PWD/bin

include(../../QtLicenseRuntime.pri)

SOURCES += main.cpp

win32 {
    QTLIC_SMOKE_SODIUM_DLL = $$clean_path($$PWD/../../third_party/libsodium/libsodium-win64/bin/libsodium-26.dll)
    QMAKE_POST_LINK += $$quote($$QMAKE_COPY "$$shell_path($$QTLIC_SMOKE_SODIUM_DLL)" "$$shell_path($$DESTDIR)")
}
