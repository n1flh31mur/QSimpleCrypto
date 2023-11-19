/*
 * Copyright 2023 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
 */

#ifndef QRSA_H
#define QRSA_H

#include "QSimpleCrypto_global.h"

#include <QFile>
#include <QObject>

#include <memory>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace QSimpleCrypto {
class QSIMPLECRYPTO_EXPORT QRsa {

public:
    QRsa();

    ///
    /// \brief QSimpleCrypto::QRSA::generateRsaKeys - Function generate Rsa Keys and returns them in OpenSSL structure.
    /// \param bits - RSA key size. For example: 2048, 4096.
    /// \param rsaBigNumber - The exponent is an odd number, typically 3, 17 or 65537.
    ///
    /// \details In order to maintain adequate security level, the maximum number of permitted primes depends on modulus bit length:
    ///
    ///          <1024 | >=1024 | >=4096 | >=8192
    ///          ------+--------+--------+-------
    ///            2   |   3    |   4    |   5
    ///
    ///          https://www.openssl.org/docs/manmaster/man3/RSA_generate_key_ex.html
    ///
    /// \return Returns 'OpenSSL RSA structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'RSA_free()' to avoid memory leak.
    ///
    [[nodiscard]] EVP_PKEY* generateRsaKeys(quint32 bits = 2048, quint32 rsaBigNumber = 3);

    ///
    /// \brief savePublicKey - Saves to file RSA public key.
    /// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
    /// \param filePath - Path and file name where the file will be saved. Example: "/root/ca.pem"
    ///
    void savePublicKey(EVP_PKEY* key, const QByteArray& filePath);

    ///
    /// \brief savePrivateKey - Saves to file RSA private key.
    /// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
    /// \param filePath - Path and file name where the file will be saved. Example: "/root/ca.pem"
    /// \param password - Private key password.
    /// \param cipher - Can be used with 'OpenSSL EVP_CIPHER' (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc().
    ///
    void savePrivateKey(EVP_PKEY* key, const QByteArray& filePath, QByteArray password = "", const EVP_CIPHER* cipher = nullptr);

    ///
    /// \brief getPublicKeyFromFile - Gets RSA public key from a file.
    /// \param filePath - File path to public key file.
    /// \return Returns 'OpenSSL EVP_PKEY structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak.
    ///
    [[nodiscard]] EVP_PKEY* getPublicKeyFromFile(const QByteArray& filePath);

    ///
    /// \brief getPrivateKeyFromFile - Gets RSA private key from a file.
    /// \param filePath - File path to private key file.
    /// \param password - Private key password.
    /// \return Returns 'OpenSSL EVP_PKEY structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak.
    ///
    [[nodiscard]] EVP_PKEY* getPrivateKeyFromFile(const QByteArray& filePath, const QByteArray& password = "");

    ///
    /// \brief encrypt - Encrypt data with RSA algorithm.
    /// \param plaintext - Text that must be encrypted.
    /// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
    /// \param padding - OpenSSL RSA padding can be used with: 'RSA_PKCS1_PADDING', 'RSA_NO_PADDING' and etc.
    /// \return Returns encrypted data on success or "" on failure.
    ///
    [[nodiscard]] QByteArray encrypt(QByteArray plainText, EVP_PKEY* rsa, const quint16 padding = RSA_PKCS1_OAEP_PADDING);

    ///
    /// \brief decrypt - Decrypt data with RSA algorithm.
    /// \param cipherText - Text that must be decrypted.
    /// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
    /// \param padding - RSA padding can be used with: 'RSA_PKCS1_PADDING', 'RSA_NO_PADDING' and etc.
    /// \return Returns encrypted data on success or "" on failure.
    ///
    [[nodiscard]] QByteArray decrypt(QByteArray cipherText, EVP_PKEY* key, const quint16 padding = RSA_PKCS1_OAEP_PADDING);
};
} // namespace QSimpleCrypto

#endif // QRSA_H
