/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef ENCRYPT_AEAD_H
#define ENCRYPT_AEAD_H

#include <QDebug>
#include <QObject>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace QSimpleCrypto
{
    class AuthenticatedEncryption {
    public:
        AuthenticatedEncryption();

        QByteArray encrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
            QByteArray key, QByteArray iv,
            QByteArray aad, QByteArray *tag);
        QByteArray decrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
            QByteArray key, QByteArray iv,
            QByteArray aad, QByteArray *tag);

        QByteArray encrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
            QByteArray key, QByteArray iv,
            QByteArray aad, QByteArray *tag);
        QByteArray decrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
            QByteArray key, QByteArray iv,
            QByteArray aad, QByteArray *tag);
    };
} // namespace QSimpleCrypto

#endif // ENCRYPT_AEAD_H
