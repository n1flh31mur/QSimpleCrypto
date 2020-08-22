/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef ENCRYPT_RSA_H
#define ENCRYPT_RSA_H

#include <QDebug>
#include <QFile>
#include <QObject>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace QSimpleCrypto
{
    class RSAEncryption {

    #define PUBLIC_ENCRYPT 0
    #define PRIVATE_ENCRYPT 1
    #define PUBLIC_DECRYPT 2
    #define PRIVATE_DECRYPT 3

    public:
        RSAEncryption();

        RSA* generate_rsa_keys(const int& bits, const int& rsaBigNumber);

        void save_rsa_publicKey(const RSA* rsa, const QByteArray& publicKeyFileName);
        void save_rsa_privateKey(RSA* rsa, const QByteArray& privateKeyFileName,
            QByteArray password = "", const EVP_CIPHER* cipher = nullptr);

        QByteArray get_rsa_key_from_file(const QString& rsaKeyFilePath);

        QByteArray encrypt(QByteArray plainText, RSA* rsa, const int& encryptType = PUBLIC_ENCRYPT, const int& padding = RSA_PKCS1_PADDING);
        QByteArray decrypt(QByteArray cipherText, RSA* rsa, const int& decryptType = PRIVATE_DECRYPT, const int& padding = RSA_PKCS1_PADDING);
    };
} // namespace QSimpleCrypto

#endif // ENCRYPT_RSA_H
