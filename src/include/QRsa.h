/**
 * Copyright 2021 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
 **/

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
    /// \brief The EncryptTypes enum - RSA algorithm encrypt types.
    ///
    enum EncryptTypes {
        PublicEncrypt,
        PrivateEncrypt
    };

    ///
    /// \brief The DecryptTypes enum - RSA algorithm decrypt types.
    ///
    enum DecryptTypes {
        PublicDecrypt,
        PrivateDecrypt
    };

    ///
    /// \brief generateRsaKeys - Function generate Rsa Keys and returns them in OpenSSL structure.
    /// \param bits - RSA key size.
    /// \param rsaBigNumber - The exponent is an odd number, typically 3, 17 or 65537.
    /// \return Returns 'OpenSSL RSA structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'RSA_free()' to avoid memory leak.
    ///
    [[nodiscard]] RSA* generateRsaKeys(const qint32& bits, const qint32& rsaBigNumber);

    ///
    /// \brief savePublicKey - Saves to file RSA public key.
    /// \param rsa - OpenSSL RSA structure.
    /// \param publicKeyFileName - Public key file name.
    ///
    void savePublicKey(RSA* rsa, const QByteArray& publicKeyFileName);

    ///
    /// \brief savePrivateKey - Saves to file RSA private key.
    /// \param rsa - OpenSSL RSA structure.
    /// \param privateKeyFileName - Private key file name.
    /// \param password - Private key password.
    /// \param cipher - Can be used with 'OpenSSL EVP_CIPHER' (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc().
    ///
    void savePrivateKey(RSA* rsa, const QByteArray& privateKeyFileName, QByteArray password = "", const EVP_CIPHER* cipher = nullptr);

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
    /// \return - Returns 'OpenSSL EVP_PKEY structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak.
    ///
    [[nodiscard]] EVP_PKEY* getPrivateKeyFromFile(const QByteArray& filePath, const QByteArray& password = "");

    ///
    /// \brief encrypt - Encrypt data with RSA algorithm.
    /// \param plaintext - Text that must be encrypted.
    /// \param rsa - OpenSSL RSA structure.
    /// \param encryptType - Public or private encrypt type. (PUBLIC_ENCRYPT, PRIVATE_ENCRYPT).
    /// \param padding - OpenSSL RSA padding can be used with: 'RSA_PKCS1_PADDING', 'RSA_NO_PADDING' and etc.
    /// \return Returns encrypted data or "", if error happened.
    ///
    [[nodiscard]] QByteArray encrypt(QByteArray plainText, RSA* rsa, const EncryptTypes encryptType = EncryptTypes::PublicEncrypt, const int& padding = RSA_PKCS1_PADDING);

    ///
    /// \brief decrypt - Decrypt data with RSA algorithm.
    /// \param cipherText - Text that must be decrypted.
    /// \param rsa - OpenSSL RSA structure.
    /// \param decryptType - Public or private type. (PUBLIC_DECRYPT, PRIVATE_DECRYPT).
    /// \param padding  - RSA padding can be used with: 'RSA_PKCS1_PADDING', 'RSA_NO_PADDING' and etc.
    /// \return - Returns decrypted data or "", if error happened.
    ///
    [[nodiscard]] QByteArray decrypt(QByteArray cipherText, RSA* rsa, const DecryptTypes decryptType = DecryptTypes::PrivateDecrypt, const int& padding = RSA_PKCS1_PADDING);
};
} // namespace QSimpleCrypto

#endif // QRSA_H