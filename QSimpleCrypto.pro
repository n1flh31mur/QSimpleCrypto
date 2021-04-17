QT -= gui

TEMPLATE = lib

CONFIG += c++17
CONFIG += staticlib

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += \
    include/QAead.h \
    include/QBlockCipher.h \
    include/QCryptoError.h \
    include/QRsa.h \
    include/QSimpleCrypto_global.h \
    include/QX509.h \
    include/QX509Store.h

SOURCES += \
    sources/QCryptoError.cpp \
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

# Add OpenSSL lib
unix:!macx: LIBS += -L$$PWD/../../../Qt/Tools/OpenSSL/binary/lib/ -lcrypto

INCLUDEPATH += $$PWD/OpenSSL/binary/include/openssl
DEPENDPATH += $$PWD/OpenSSL/binary/include/openssl

unix:!macx: PRE_TARGETDEPS += $$PWD/OpenSSL/binary/lib/libcrypto.a
unix:!macx: PRE_TARGETDEPS += $$PWD/OpenSSL/binary/lib/libssl.a
