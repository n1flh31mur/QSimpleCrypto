/*
 * Copyright 2023 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
 */

#ifndef QAEAD_H
#define QAEAD_H

#include "QSimpleCrypto_global.h"

#include <QObject>

#include <memory>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace QSimpleCrypto {
class QSIMPLECRYPTO_EXPORT QAead {
public:
    QAead();

    ///
    /// \brief encryptAesGcm - Function encrypts data with AES GCM algorithm.
    /// \param data - Data that will be encrypted.
    /// \param key - AES key. Example: "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT"
    /// \param iv - Initialization vector. Example: "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT"
    /// \param tag - Authorization tag. Example: "AABBCCDDEEFF"
    /// \param aad - Additional authenticated data.
    /// \param cipher - Can be used with OpenSSL EVP_CIPHER (gcm) - 128, 192, 256. Example: EVP_aes_256_gcm().
    /// \return Returns encrypted data on success or "" on failure.
    ///
    [[nodiscard]] QByteArray encryptAesGcm(const QByteArray& data, const QByteArray& key, const QByteArray& iv, const QByteArray& tag, const QByteArray& aad = "", const EVP_CIPHER* cipher = EVP_aes_256_gcm());

    ///
    /// \brief decryptAesGcm - Function decrypts data with AES GCM algorithm.
    /// \param data - Data that will be decrypted
    /// \param key - AES key. Example: "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT"
    /// \param iv - Initialization vector. Example: "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT"
    /// \param tag - Authorization tag. Example: "AABBCCDDEEFF"
    /// \param aad - Additional authenticated data.
    /// \param cipher - Can be used with OpenSSL EVP_CIPHER (gcm) - 128, 192, 256. Example: EVP_aes_256_gcm()
    /// \return Returns decrypted data on success or "" on failure.
    ///
    [[nodiscard]] QByteArray decryptAesGcm(const QByteArray& data, const QByteArray& key, const QByteArray& iv, const QByteArray& tag, const QByteArray& aad = "", const EVP_CIPHER* cipher = EVP_aes_256_gcm());

    ///
    /// \brief encryptAesCcm - Function encrypts data with AES CCM algorithm.
    /// \param data - Data that will be encrypted.
    /// \param key - AES key. Example: "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT"
    /// \param iv - Initialization vector. Example: "AABBCCDDEEFF"
    /// \param tag - Authorization tag. Example: "AABBCCDDEEFF"
    /// \param aad - Additional authenticated data.
    /// \param cipher - Can be used with OpenSSL EVP_CIPHER (ccm) - 128, 192, 256. Example: EVP_aes_256_ccm().
    /// \return Returns encrypted data on success or "" on failure.
    ///
    [[nodiscard]] QByteArray encryptAesCcm(const QByteArray& data, const QByteArray& key, const QByteArray& iv, const QByteArray& tag, const QByteArray& aad = "", const EVP_CIPHER* cipher = EVP_aes_256_ccm());

    ///
    /// \brief decryptAesCcm - Function decrypts data with AES CCM algorithm.
    /// \param data - Data that will be decrypted.
    /// \param key - AES key. Example: "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT"
    /// \param iv - Initialization vector. Example: "AABBCCDDEEFF"
    /// \param tag - Authorization tag. Example: "AABBCCDDEEFF"
    /// \param aad - Additional authenticated data.
    /// \param cipher - Can be used with OpenSSL EVP_CIPHER (ccm) - 128, 192, 256. Example: EVP_aes_256_ccm().
    /// \return Returns decrypted data on success or "" on failure.
    ///
    [[nodiscard]] QByteArray decryptAesCcm(const QByteArray& data, const QByteArray& key, const QByteArray& iv, const QByteArray& tag, const QByteArray& aad = "", const EVP_CIPHER* cipher = EVP_aes_256_ccm());
};
} // namespace QSimpleCrypto

#endif // QAEAD_H
