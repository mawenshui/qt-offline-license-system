QT -= gui
QT += core

TEMPLATE = lib
CONFIG += staticlib c++14 warn_on
TARGET = QtLicenseCore

LICENSESYSTEM_ROOT = $$clean_path($$PWD/..)
SODIUM_ROOT = $$LICENSESYSTEM_ROOT/third_party/libsodium
DESTDIR = $$LICENSESYSTEM_ROOT/bin/lib
OBJECTS_DIR = $$OUT_PWD/obj
MOC_DIR = $$OUT_PWD/moc

include($$LICENSESYSTEM_ROOT/third_party/libsodium/libsodium.pri)

HEADERS += \
    audit_logger.h \
    batch_issuer.h \
    crypto_provider.h \
    hardware_fingerprint.h \
    key_vault.h \
    license_codec.h \
    license_runtime.h \
    license_types.h \
    offline_time_guard.h \
    runtime_compatibility.h \
    version.h

SOURCES += \
    audit_logger.cpp \
    batch_issuer.cpp \
    crypto_provider.cpp \
    hardware_fingerprint.cpp \
    key_vault.cpp \
    license_codec.cpp \
    license_runtime.cpp \
    license_types.cpp \
    offline_time_guard.cpp \
    runtime_compatibility.cpp

win32: LIBS += -lcrypt32
