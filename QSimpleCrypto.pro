QT -= gui

TEMPLATE = lib

CONFIG += c++17
CONFIG += staticlib

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    QAEAD.cpp \
    QBlockCipher.cpp \
    QRSA.cpp \
    QX509.cpp \
    QX509Store.cpp

HEADERS += \
    QAEAD.h \
    QBlockCipher.h \
    QRSA.h \
    QSimpleCrypto_global.h \
    QX509.h \
    QX509Store.h

# Default rules for deployment.
unix {
    target.path = $$[QT_INSTALL_PLUGINS]/generic
}
!isEmpty(target.path): INSTALLS += target
