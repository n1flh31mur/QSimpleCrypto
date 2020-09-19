/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QAEAD_H
#define QAEAD_H

#include "QSimpleCrypto_global.h"

#include <QDebug>
#include <QObject>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace QSimpleCrypto
{
    class QSIMPLECRYPTO_EXPORT QAEAD {
    public:
        QAEAD();

        QByteArray encryptAesGcm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad, const EVP_CIPHER* cipher = EVP_aes_256_gcm());
        QByteArray decryptAesGcm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad = "", const EVP_CIPHER* cipher = EVP_aes_256_gcm());

        QByteArray encryptAesCcm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad = "", const EVP_CIPHER* cipher = EVP_aes_256_ccm());
        QByteArray decryptAesCcm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad = "", const EVP_CIPHER* cipher = EVP_aes_256_ccm());
    };
} // namespace QSimpleCrypto

#endif // QAEAD_H
