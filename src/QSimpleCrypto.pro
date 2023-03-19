QT -= gui

TEMPLATE = lib

CONFIG += c++17
CONFIG += staticlib

HEADERS += \
    include/QAead.h \
    include/QBlockCipher.h \
    include/QRsa.h \
    include/QSimpleCrypto_global.h \
    include/QX509.h \
    include/QX509Store.h

SOURCES += \
    sources/QAead.cpp \
    sources/QBlockCipher.cpp \
    sources/QRsa.cpp \
    sources/QX509.cpp \
    sources/QX509Store.cpp

# Default rules for deployment.
unix {
    target.path = $$[QT_INSTALL_PLUGINS]/generic
}
!isEmpty(target.path): INSTALLS += target

# Include OpenSSL for unix
unix {
    unix: LIBS += -L$$PWD/libs/OpenSSL/unix/ -lcrypto
    unix: LIBS += -L$$PWD/libs/OpenSSL/unix/ -lssl

    INCLUDEPATH += $$PWD/libs/OpenSSL/unix/include
    DEPENDPATH += $$PWD/libs/OpenSSL/unix/include
}

# Include OpenSSL for android
android {
    INCLUDEPATH += $$PWD/libs/OpenSSL/android/no-asm/static/include/
    DEPENDPATH += $$PWD/libs/OpenSSL/android/no-asm/static/include/

    android: include($$PWD/libs/OpenSSL/android/openssl.pri)
}
