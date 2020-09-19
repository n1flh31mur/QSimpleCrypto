QT -= gui

TEMPLATE = lib

CONFIG += c++17
CONFIG += staticlib

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    sources/QAEAD.cpp \
    sources/QBlockCipher.cpp \
    sources/QRSA.cpp \
    sources/QX509.cpp \
    sources/QX509Store.cpp

HEADERS += \
    include/QAEAD.h \
    include/QBlockCipher.h \
    include/QRSA.h \
    include/QSimpleCrypto_global.h \
    include/QX509.h \
    include/QX509Store.h

# Default rules for deployment.
unix {
    target.path = $$[QT_INSTALL_PLUGINS]/generic
}
!isEmpty(target.path): INSTALLS += target
