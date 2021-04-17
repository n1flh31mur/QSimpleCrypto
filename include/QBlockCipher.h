/**
 * Copyright 2021 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QBLOCKCIPHER_H
#define QBLOCKCIPHER_H

#include "QSimpleCrypto_global.h"

#include <QObject>

#include <memory>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "QCryptoError.h"

// clang-format off
namespace QSimpleCrypto
{
    class QSIMPLECRYPTO_EXPORT QBlockCipher {

    #define Aes128Rounds 10
    #define Aes192Rounds 12
    #define Aes256Rounds 14

    public:
        QBlockCipher();

        ///
        /// \brief generateRandomBytes - Function generates random bytes by size.
        /// \param size - Size of generated bytes.
        /// \return Returns random bytes.
        ///
        QByteArray generateRandomBytes(const int& size);

        ///
        /// \brief encryptAesBlockCipher - Function encrypts data with Aes Block Cipher algorithm.
        /// \param data - Data that will be encrypted.
        /// \param key - AES key.
        /// \param iv - Initialization vector.
        /// \param password - Encryption password.
        /// \param salt - Random delta.
        /// \param rounds - Transformation rounds.
        /// \param chiper - Can be used with OpenSSL EVP_CIPHER (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc().
        /// \param md - Hash algroitm (OpenSSL EVP_MD). Example: EVP_sha512().
        /// \return Returns decrypted data or "", if error happened.
        ///
        QByteArray encryptAesBlockCipher(QByteArray data, QByteArray key,
            QByteArray iv = "", QByteArray password = "",
            QByteArray salt = "", const int& rounds = Aes256Rounds,
            const EVP_CIPHER* cipher = EVP_aes_256_cbc(), const EVP_MD* md = EVP_sha512());

        ///
        /// \brief decryptAesBlockCipher - Function decrypts data with Aes Block Cipher algorithm.
        /// \param data - Data that will be decrypted.
        /// \param key - AES key.
        /// \param iv - Initialization vector.
        /// \param password - Decryption password.
        /// \param salt - Random delta.
        /// \param rounds - Transformation rounds.
        /// \param chiper - Can be used with OpenSSL EVP_CIPHER (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc().
        /// \param md - Hash algroitm (OpenSSL EVP_MD). Example: EVP_sha512().
        /// \return Returns decrypted data or "", if error happened.
        ///
        QByteArray decryptAesBlockCipher(QByteArray data, QByteArray key,
            QByteArray iv = "", QByteArray password = "",
            QByteArray salt = "", const int& rounds = Aes256Rounds,
            const EVP_CIPHER* cipher = EVP_aes_256_cbc(), const EVP_MD* md = EVP_sha512());

        ///
        /// \brief error - Error handler class.
        ///
        QCryptoError error;
    };
} // namespace QSimpleCrypto

#endif // QBLOCKCIPHER_H
