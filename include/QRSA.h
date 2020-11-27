/**
 * Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QRSA_H
#define QRSA_H

#include "QSimpleCrypto_global.h"

#include <QDebug>
#include <QFile>
#include <QObject>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace QSimpleCrypto
{
    class QSIMPLECRYPTO_EXPORT QRSA {

    #define PublicEncrypt 0
    #define PrivateEncrypt 1
    #define PublicDecrypt 2
    #define PrivateDecrypt 3

    public:
        QRSA();

        RSA* generateRsaKeys(const int& bits, const int& rsaBigNumber);

        void savePublicKey(RSA *rsa, const QByteArray& publicKeyFileName);
        void savePrivateKey(RSA* rsa, const QByteArray& privateKeyFileName, QByteArray password = "", const EVP_CIPHER* cipher = nullptr);

        EVP_PKEY* getPublicKeyFromFile(const QByteArray& filePath);
        EVP_PKEY* getPrivateKeyFromFile(const QByteArray& filePath, const QByteArray& password = "");

        QByteArray encrypt(QByteArray plainText, RSA* rsa, const int& encryptType = PublicEncrypt, const int& padding = RSA_PKCS1_PADDING);
        QByteArray decrypt(QByteArray cipherText, RSA* rsa, const int& decryptType = PrivateDecrypt, const int& padding = RSA_PKCS1_PADDING);
    };
} // namespace QSimpleCrypto

#endif // QRSA_H
