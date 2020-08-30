/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QBLOCKCIPHER_H
#define QBLOCKCIPHER_H

#include <QDebug>
#include <QObject>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace QSimpleCrypto
{
    class QBlockCipher {
    public:
        QBlockCipher();
        QByteArray generateRandomBytes(const int& size);

        QByteArray encryptAesBlockCipher(QByteArray data, QByteArray key,
            QByteArray iv = "", QByteArray password = "",
            QByteArray salt = "", const int& rounds = 14,
            const EVP_CIPHER* cipher = EVP_aes_256_cbc(), const EVP_MD* md = EVP_sha512());

        QByteArray decryptAesBlockCipher(QByteArray data, QByteArray key,
            QByteArray iv = "", QByteArray password = "",
            QByteArray salt = "", const int& rounds = 14,
            const EVP_CIPHER* cipher = EVP_aes_256_cbc(), const EVP_MD* md = EVP_sha512());
    };
} // namespace QSimpleCrypto

#endif // QBLOCKCIPHER_H
