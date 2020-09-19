﻿/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "include/QRSA.h"

QSimpleCrypto::QRSA::QRSA()
{
}

///
/// \brief QRSA::generateRsaKeys
/// \param bits - key size (1024 to 4096)
/// \param rsaBigNumber - The exponent is an odd number, typically 3, 17 or 65537.
/// \return - returned value must be cleaned up with 'RSA_free()' to avoid memory leak
///
RSA* QSimpleCrypto::QRSA::generateRsaKeys(const int& bits, const int& rsaBigNumber)
{
    /* Initialize big number */
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> bigNumber { BN_new(), BN_free };
    if (bigNumber == nullptr) {
        qCritical() << "Couldn't initialize bigNumber. BN_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Set big number */
    if (!BN_set_word(bigNumber.get(), rsaBigNumber)) {
        qCritical() << "Couldn't set bigNumber. BN_set_word() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Initialize RSA */
    RSA* rsa = nullptr;
    if (!(rsa = RSA_new())) {
        qCritical() << "Couldn't initialize x509. X509_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Generate key pair and store it in RSA */
    if (!RSA_generate_key_ex(rsa, bits, bigNumber.get(), nullptr)) {
        qCritical() << "Couldn't generate RSA. RSA_generate_key_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    return rsa;
}

///
/// \brief QRSA::savePublicKey
/// \param rsa - openssl RSA structure
/// \param publicKeyFileName - file name of public key file
///
void QSimpleCrypto::QRSA::savePublicKey(RSA* rsa, const QByteArray& publicKeyFileName)
{
    /* Initialize BIO */
    std::unique_ptr<BIO, void (*)(BIO*)> bioPublicKey { BIO_new_file(publicKeyFileName.data(), "w+"), BIO_free_all };
    if (bioPublicKey == nullptr) {
        qCritical() << "Couldn't initialize bioPublicKey. BIO_new_file() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return;
    }

    /* Write public key on file */
    if (!PEM_write_bio_RSA_PUBKEY(bioPublicKey.get(), rsa)) {
        qCritical() << "Couldn't save public key. PEM_write_bio_RSAPublicKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }
}

///
/// \brief QRSA::savePrivateKey
/// \param rsa - openssl RSA structure
/// \param privateKeyFileName - file name of private key file
/// \param password - private key password
/// \param cipher - evp cipher. Can be used with openssl evp chipers (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_ecb()
///
void QSimpleCrypto::QRSA::savePrivateKey(RSA* rsa, const QByteArray& privateKeyFileName,
    QByteArray password, const EVP_CIPHER* cipher)
{
    /* Initialize BIO */
    std::unique_ptr<BIO, void (*)(BIO*)> bioPrivateKey { BIO_new_file(privateKeyFileName.data(), "w+"), BIO_free_all };
    if (bioPrivateKey == nullptr) {
        qCritical() << "Couldn't initialize bioPrivateKey. BIO_new_file() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return;
    }

    /* Write private key to file */
    if (!PEM_write_bio_RSAPrivateKey(bioPrivateKey.get(), rsa, cipher, reinterpret_cast<unsigned char*>(password.data()), password.size(), nullptr, nullptr)) {
        qCritical() << "Couldn't save private key. PEM_write_bio_RSAPrivateKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }
}

///
/// \brief QRSA::getPublicKeyFromFile - gets a key from a file
/// \param filePath
/// \return - returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak
///
EVP_PKEY* QSimpleCrypto::QRSA::getPublicKeyFromFile(const QByteArray& filePath)
{
    /* Initialize BIO */
    std::unique_ptr<BIO, void (*)(BIO*)> bioPublicKey { BIO_new_file(filePath.data(), "r"), BIO_free_all };
    if (bioPublicKey == nullptr) {
        qCritical() << "Couldn't initialize bioPublicKey. BIO_new_file() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Initialize EVP_PKEY */
    EVP_PKEY* keyStore = nullptr;
    if (!(keyStore = EVP_PKEY_new())) {
        qCritical() << "Couldn't initialize keyStore. EVP_PKEY_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Write private key to file */
    if (!PEM_read_bio_PUBKEY(bioPublicKey.get(), &keyStore, nullptr, nullptr)) {
        qCritical() << "Couldn't read private key. PEM_read_bio_PrivateKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    return keyStore;
}

///
/// \brief QRSA::getPrivateKeyFromFile - gets a key from a file
/// \param filePath
/// \param password
/// \return - returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak
///
EVP_PKEY* QSimpleCrypto::QRSA::getPrivateKeyFromFile(const QByteArray& filePath, const QByteArray& password)
{
    /* Initialize BIO */
    std::unique_ptr<BIO, void (*)(BIO*)> bioPrivateKey { BIO_new_file(filePath.data(), "r"), BIO_free_all };
    if (bioPrivateKey == nullptr) {
        qCritical() << "Couldn't initialize bioPrivateKey. BIO_new_file() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Initialize EVP_PKEY */
    EVP_PKEY* keyStore = nullptr;
    if (!(keyStore = EVP_PKEY_new())) {
        qCritical() << "Couldn't initialize keyStore. EVP_PKEY_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Write private key to file */
    if (!PEM_read_bio_PrivateKey(bioPrivateKey.get(), &keyStore, nullptr, (void*)password.data())) {
        qCritical() << "Couldn't read private key. PEM_read_bio_PrivateKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    return keyStore;
}

///
/// \brief QSimpleCrypto::QRSA::encrypt
/// \param plaintext - text that must be encrypted
/// \param rsa - openssl RSA structure
/// \param decryptType - public or decrypt type. (PUBLIC_DECRYPT, PRIVATE_DECRYPT)
/// \param padding  - RSA padding can be used with: RSA_PKCS1_PADDING, RSA_NO_PADDING and etc
/// \return
///
QByteArray QSimpleCrypto::QRSA::encrypt(QByteArray plainText, RSA* rsa, const int& encryptType, const int& padding)
{
    /* Initialize array. Here encrypted data will be saved */
    std::unique_ptr<unsigned char[]> cipherText { new unsigned char[RSA_size(rsa)]() };
    if (cipherText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'ciphertext\'.";
        return "";
    }

    /* Result of encryption operation */
    short int result = 0;

    /* Execute encryption operation */
    if (encryptType == PUBLIC_ENCRYPT) {
        result = RSA_public_encrypt(plainText.size(), reinterpret_cast<unsigned char*>(plainText.data()), cipherText.get(), rsa, padding);
    } else if (encryptType == PRIVATE_ENCRYPT) {
        result = RSA_private_encrypt(plainText.size(), reinterpret_cast<unsigned char*>(plainText.data()), cipherText.get(), rsa, padding);
    }

    /* Check for result */
    if (result <= -1) {
        qCritical() << "Couldn't encrypt data. Error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Get encrypted data */
    const QByteArray& encryptedData = QByteArray(reinterpret_cast<char*>(cipherText.get()), RSA_size(rsa));

    return encryptedData;
}

///
/// \brief QSimpleCrypto::QRSA::decrypt
/// \param cipherText - text that must be decrypted
/// \param rsa - openssl RSA structure
/// \param decryptType - public or decrypt type. (PUBLIC_DECRYPT, PRIVATE_DECRYPT)
/// \param padding  - RSA padding can be used with: RSA_PKCS1_PADDING, RSA_NO_PADDING and etc
/// \return
///
QByteArray QSimpleCrypto::QRSA::decrypt(QByteArray cipherText, RSA* rsa, const int& decryptType, const int& padding)
{
    /* Initialize array. Here decrypted data will be saved */
    std::unique_ptr<unsigned char[]> plainText { new unsigned char[cipherText.size()]() };
    if (plainText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'plaintext\'.";
        return "";
    }

    /* Result of decryption operation */
    short int result = 0;

    /* Execute decryption operation */
    if (decryptType == PUBLIC_DECRYPT) {
        result = RSA_public_decrypt(RSA_size(rsa), reinterpret_cast<unsigned char*>(cipherText.data()), plainText.get(), rsa, padding);
    } else if (decryptType == PRIVATE_DECRYPT) {
        result = RSA_private_decrypt(RSA_size(rsa), reinterpret_cast<unsigned char*>(cipherText.data()), plainText.get(), rsa, padding);
    }

    /* Check for result */
    if (result <= -1) {
        qCritical() << "Couldn't decrypt data. Error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Get decrypted data */
    const QByteArray& decryptedData = QByteArray(reinterpret_cast<char*>(plainText.get()));

    return decryptedData;
}