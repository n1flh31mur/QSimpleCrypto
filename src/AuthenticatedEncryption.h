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

// clang-format off
namespace QSimpleCrypto
{
    class AuthenticatedEncryption {
    public:
        AuthenticatedEncryption();

        QByteArray encrypt_aes_gcm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad, const EVP_CIPHER* cipher = EVP_aes_256_gcm());
        QByteArray decrypt_aes_gcm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad = "", const EVP_CIPHER* cipher = EVP_aes_256_gcm());

        QByteArray encrypt_aes_ccm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad= "", const EVP_CIPHER* cipher = EVP_aes_256_ccm());
        QByteArray decrypt_aes_ccm(QByteArray data, QByteArray key,
            QByteArray iv, QByteArray* tag,
            QByteArray aad = "", const EVP_CIPHER* cipher = EVP_aes_256_ccm());
    };
} // namespace QSimpleCrypto

#endif // ENCRYPT_AEAD_H
