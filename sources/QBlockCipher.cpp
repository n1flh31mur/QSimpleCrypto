/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "include/QBlockCipher.h"

QSimpleCrypto::QBlockCipher::QBlockCipher()
{
}

///
/// \brief QSimpleCrypto::QBlockCipher::generateRandomBytes - Can be used for 'Random delta (salt)'
/// \param size - size of random bytes
/// \return
///
QByteArray QSimpleCrypto::QBlockCipher::generateRandomBytes(const int& size)
{
    unsigned char arr[sizeof(size)];
    RAND_bytes(arr, sizeof(size));

    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

///
/// \brief QSimpleCrypto::QBlockCipher::encryptAesBlockCipher
/// \param data - Data that will be encrypted
/// \param key - AES key
/// \param iv - Initialization vector
/// \param password - Encryption password
/// \param salt - Random delta
/// \param rounds - Transformation rounds
/// \param chiper - Can be used with OpenSSL EVP_CIPHER (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc()
/// \param md - Hash algroitm (OpenSSL EVP_MD). Example: EVP_sha512()
/// \return Returns encrypted data
///
QByteArray QSimpleCrypto::QBlockCipher::encryptAesBlockCipher(QByteArray data, QByteArray key,
    QByteArray iv, QByteArray password, QByteArray salt,
    const int& rounds, const EVP_CIPHER* cipher, const EVP_MD* md)
{
    /* Initialize EVP_CIPHER_CTX */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> en { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
    if (en == nullptr) {
        qCritical() << "Couldn't initialize evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    unsigned char* m_key = reinterpret_cast<unsigned char*>(key.data());
    unsigned char* m_iv = reinterpret_cast<unsigned char*>(iv.data());

    /* Set data length */
    int cipherTextLength(data.size() + AES_BLOCK_SIZE);
    int finalLength = 0;

    /* Initialize cipcherText. Here encrypted data will be stored */
    std::unique_ptr<unsigned char[]> cipherText { new unsigned char[cipherTextLength]() };
    if (cipherText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'cipherText\'.";
        return QByteArray();
    }

    /* Start encryption with password based encryption routine */
    if (!EVP_BytesToKey(cipher, md, reinterpret_cast<unsigned char*>(salt.data()), reinterpret_cast<unsigned char*>(password.data()), password.length(), rounds, m_key, m_iv)) {
        qCritical() << "Couldn't start encryption routine. EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Initialize encryption operation. */
    if (!EVP_EncryptInit_ex(en.get(), cipher, nullptr, m_key, m_iv)) {
        qCritical() << "Couldn't initialize encryption operation. EVP_EncryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en.get(), cipherText.get(), &cipherTextLength, reinterpret_cast<const unsigned char*>(data.data()), data.size())) {
        qCritical() << "Couldn't provide message to be encrypted. EVP_EncryptUpdate() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finalize the encryption. Normally ciphertext bytes may be written at this stage */
    if (!EVP_EncryptFinal(en.get(), cipherText.get() + cipherTextLength, &finalLength)) {
        qCritical() << "Couldn't finalize encryption. EVP_EncryptFinal() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray encryptedData = QByteArray(reinterpret_cast<char*>(cipherText.get()), cipherTextLength + finalLength);

    return encryptedData;
}

///
/// \brief QSimpleCrypto::QBlockCipher::encryptAesBlockCipher
/// \param data - Data that will be decrypted
/// \param key - AES key
/// \param iv - Initialization vector
/// \param password - Decryption password
/// \param salt - Random delta
/// \param rounds - Transformation rounds
/// \param chiper - Can be used with OpenSSL EVP_CIPHER (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc()
/// \param md - Hash algroitm (OpenSSL EVP_MD). Example: EVP_sha512()
/// \return Returns decrypted data
///
QByteArray QSimpleCrypto::QBlockCipher::decryptAesBlockCipher(QByteArray data, QByteArray key,
    QByteArray iv, QByteArray password, QByteArray salt,
    const int& rounds, const EVP_CIPHER* cipher, const EVP_MD* md)
{
    /* Initialize EVP_CIPHER_CTX */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> de { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
    if (de == nullptr) {
        qCritical() << "Couldn't initialize evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    unsigned char* m_key = reinterpret_cast<unsigned char*>(key.data());
    unsigned char* m_iv = reinterpret_cast<unsigned char*>(iv.data());

    /* Set data length */
    int plainTextLength(data.size());
    int finalLength = 0;

    /* Initialize plainText. Here decrypted data will be stored */
    std::unique_ptr<unsigned char[]> plainText { new unsigned char[plainTextLength + AES_BLOCK_SIZE]() };
    if (plainText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'plainText\'.";
        return QByteArray();
    }

    /* Start encryption with password based encryption routine */
    if (!EVP_BytesToKey(cipher, md, reinterpret_cast<const unsigned char*>(salt.data()), reinterpret_cast<const unsigned char*>(password.data()), password.length(), rounds, m_key, m_iv)) {
        qCritical() << "Couldn't start decryption routine. EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Initialize decryption operation. */
    if (!EVP_DecryptInit_ex(de.get(), cipher, nullptr, m_key, m_iv)) {
        qCritical() << "Couldn't initialize decryption operation. EVP_DecryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(de.get(), plainText.get(), &plainTextLength, reinterpret_cast<const unsigned char*>(data.data()), data.size())) {
        qCritical() << "Couldn't provide message to be decrypted. EVP_DecryptUpdate() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Finalize the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal(de.get(), plainText.get() + plainTextLength, &finalLength)) {
        qCritical() << "Couldn't finalize decryption. EVP_DecryptFinal failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray decryptedData = QByteArray(reinterpret_cast<char*>(plainText.get()), plainTextLength + finalLength);

    return decryptedData;
}
