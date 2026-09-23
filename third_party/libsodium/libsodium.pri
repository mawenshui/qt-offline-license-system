isEmpty(SODIUM_ROOT): error("SODIUM_ROOT must be set before including libsodium.pri")

win32 {
    contains(QT_ARCH, x86_64) {
        SODIUM_PLATFORM = $$SODIUM_ROOT/libsodium-win64
    } else {
        SODIUM_PLATFORM = $$SODIUM_ROOT/libsodium-win32
    }

    INCLUDEPATH += $$SODIUM_PLATFORM/include
    LIBS += -L$$SODIUM_PLATFORM/lib -lsodium
    SODIUM_DLL = $$SODIUM_PLATFORM/bin/libsodium-26.dll

    equals(TARGET, QtLicenseCore) {
        SODIUM_RUNTIME_DESTDIR = $$clean_path($$SODIUM_ROOT/../..)/bin
        QMAKE_POST_LINK += $$quote($$QMAKE_COPY "$$shell_path($$SODIUM_DLL)" "$$shell_path($$SODIUM_RUNTIME_DESTDIR)")
    }
}

unix:!macx {
    CONFIG += link_pkgconfig
    PKGCONFIG += libsodium
}
