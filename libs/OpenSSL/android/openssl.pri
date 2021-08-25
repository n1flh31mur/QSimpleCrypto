!contains(QT.network_private.enabled_features, openssl-linked) {
    CONFIG(release, debug|release): SSL_PATH = $$PWD
                            else: SSL_PATH = $$PWD/no-asm

    equals(ANDROID_TARGET_ARCH, armeabi-v7a) {
        ANDROID_EXTRA_LIBS += \
            $$SSL_PATH/latest/arm/libcrypto_1_1.so \
            $$SSL_PATH/latest/arm/libssl_1_1.so \

            unix:!macx: LIBS += \
                -L$$PWD/latest/arm/ -lssl_1_1 \
                -L$$PWD/latest/arm/ -lcrypto_1_1 \

            unix:!macx: PRE_TARGETDEPS += \
                $$PWD/latest/arm/libssl_1_1.so \
                $$PWD/latest/arm/libcrypto_1_1.so \
    }

    equals(ANDROID_TARGET_ARCH, arm64-v8a) {
            ANDROID_EXTRA_LIBS += \
                $$SSL_PATH/latest/arm64/libcrypto_1_1.so \
                $$SSL_PATH/latest/arm64/libssl_1_1.so \

            unix:!macx: LIBS += \
                -L$$PWD/latest/arm64/ -lssl_1_1 \
                -L$$PWD/latest/arm64/ -lcrypto_1_1 \

            unix:!macx: PRE_TARGETDEPS += \
                $$PWD/latest/arm64/libssl_1_1.so \
                $$PWD/latest/arm64/libcrypto_1_1.so \
    }

    equals(ANDROID_TARGET_ARCH, x86) {
        ANDROID_EXTRA_LIBS += \
            $$SSL_PATH/latest/x86/libcrypto_1_1.so \
            $$SSL_PATH/latest/x86/libssl_1_1.so \
    }

    equals(ANDROID_TARGET_ARCH, x86_64) {
        ANDROID_EXTRA_LIBS += \
            $$SSL_PATH/latest/x86_64/libcrypto_1_1.so \
            $$SSL_PATH/latest/x86_64/libssl_1_1.so \
    }
}
