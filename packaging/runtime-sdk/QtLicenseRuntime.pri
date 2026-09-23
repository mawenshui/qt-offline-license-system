QT += core
CONFIG += c++14

QTLIC_RUNTIME_ROOT = $$clean_path($$PWD)
SODIUM_ROOT = $$QTLIC_RUNTIME_ROOT/third_party/libsodium

INCLUDEPATH += $$QTLIC_RUNTIME_ROOT/src

HEADERS += \
    $$QTLIC_RUNTIME_ROOT/src/crypto_provider.h \
    $$QTLIC_RUNTIME_ROOT/src/hardware_fingerprint.h \
    $$QTLIC_RUNTIME_ROOT/src/license_codec.h \
    $$QTLIC_RUNTIME_ROOT/src/license_runtime.h \
    $$QTLIC_RUNTIME_ROOT/src/license_types.h \
    $$QTLIC_RUNTIME_ROOT/src/offline_time_guard.h

SOURCES += \
    $$QTLIC_RUNTIME_ROOT/src/crypto_provider.cpp \
    $$QTLIC_RUNTIME_ROOT/src/hardware_fingerprint.cpp \
    $$QTLIC_RUNTIME_ROOT/src/license_codec.cpp \
    $$QTLIC_RUNTIME_ROOT/src/license_runtime.cpp \
    $$QTLIC_RUNTIME_ROOT/src/license_types.cpp \
    $$QTLIC_RUNTIME_ROOT/src/offline_time_guard.cpp

include($$SODIUM_ROOT/libsodium.pri)

win32: LIBS += -lcrypt32
