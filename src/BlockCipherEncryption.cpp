/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "BlockCipherEncryption.h"

QSimpleCrypto::BlockCipherEncryption::BlockCipherEncryption()
{
}

///
/// \brief QSimpleCrypto::BlockCipherEncryption::generate_random_bytes - generate random bytes. Can be used for 'Random delta (RD)'
/// \param size - size of random bytes
/// \return
///
QByteArray QSimpleCrypto::BlockCipherEncryption::generate_random_bytes(const int& size)
{
    unsigned char arr[sizeof(size)];
    RAND_bytes(arr, sizeof(size));

    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

///
/// \brief QSimpleCrypto::BlockCipherEncryption::encrypt_aes_block_cipher
/// \param data - bytes (data) that will be encrypted
/// \param key - AES key
/// \param iv - intilization vector
/// \param password - encryption password
/// \param salt - random delta
/// \param rounds - count of bytes shaking
/// \param chiper - can be used with openssl evp chipers (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_ecb()
/// \param md - hash algroitm (sha, md and etc). Example: EVP_sha512()
/// \return
///
QByteArray QSimpleCrypto::BlockCipherEncryption::encrypt_aes_block_cipher(
    QByteArray data, QByteArray key, QByteArray iv,
    QByteArray password, QByteArray salt,
    const int& rounds, const EVP_CIPHER* cipher, const EVP_MD* md)
{
    /* Initialise cipcher */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> en { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
    if (en == nullptr) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    unsigned char* m_key = reinterpret_cast<unsigned char*>(key.data());
    unsigned char* m_iv = reinterpret_cast<unsigned char*>(iv.data());

    /* Set length of data */
    int plainTextLength = data.size();
    int cipherTextLength(plainTextLength + AES_BLOCK_SIZE);
    int finalLength = 0;

    /* Initialise cipchertext. Here we will store encrypted data */
    std::unique_ptr<unsigned char[]> cipherText { new unsigned char[cipherTextLength]() };
    if (cipherText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'ciphertext\'.";
        return QByteArray();
    }

    /* Start encryption with password based encryption routine */
    if (!EVP_BytesToKey(cipher, md, reinterpret_cast<unsigned char*>(salt.data()), reinterpret_cast<unsigned char*>(password.data()), password.length(), rounds, m_key, m_iv)) {
        qCritical() << "Couldn't start encryption routine. EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(en.get(), cipher, nullptr, m_key, m_iv)) {
        qCritical() << "Couldn't initialise encryption operation. EVP_EncryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en.get(), cipherText.get(), &cipherTextLength, reinterpret_cast<const unsigned char*>(data.data()), plainTextLength)) {
        qCritical() << "Couldn't provide message to be encrypted. EVP_EncryptUpdate() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at this stage
    */
    if (!EVP_EncryptFinal(en.get(), cipherText.get() + cipherTextLength, &finalLength)) {
        qCritical() << "Couldn't finalise encryption. EVP_EncryptFinal_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    plainTextLength = cipherTextLength + finalLength;

    QByteArray encryptedData = QByteArray(reinterpret_cast<char*>(cipherText.get()), plainTextLength);

    return encryptedData;
}

///
/// \brief QSimpleCrypto::BlockCipherEncryption::decrypt_aes_block_cipher
/// \param data - bytes (data) that will be encrypted
/// \param key - AES key
/// \param iv - intilization vector
/// \param password - encryption password
/// \param salt - random delta
/// \param rounds - count of bytes shaking
/// \param chiper - can be used with openssl evp chipers (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_ecb()
/// \param md - hash algroitm (sha, md and etc). Example: EVP_sha512_256
/// \return
///
QByteArray QSimpleCrypto::BlockCipherEncryption::decrypt_aes_block_cipher(
    QByteArray data, QByteArray key, QByteArray iv,
    QByteArray password, QByteArray salt,
    const int& rounds, const EVP_CIPHER* cipher, const EVP_MD* md)
{
    /* Initialise cipcher */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> de { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
    if (de == nullptr) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    unsigned char* m_key = reinterpret_cast<unsigned char*>(key.data());
    unsigned char* m_iv = reinterpret_cast<unsigned char*>(iv.data());

    /* Set length of data */
    int dataLength = data.size();
    int plainTextLength(dataLength);
    int finalLength = 0;

    /* Initialise plaintext. Here we will store decrypted data */
    std::unique_ptr<unsigned char[]> plainText { new unsigned char[plainTextLength + AES_BLOCK_SIZE]() };
    if (plainText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'plaintext\'.";
        return QByteArray();
    }

    /* Start encryption with password based encryption routine */
    if (!EVP_BytesToKey(cipher, md, reinterpret_cast<const unsigned char*>(salt.data()), reinterpret_cast<const unsigned char*>(password.data()), password.length(), rounds, m_key, m_iv)) {
        qCritical() << "Couldn't start decryption routine. EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(de.get(), cipher, nullptr, m_key, m_iv)) {
        qCritical() << "Couldn't initialise decryption operation. EVP_DecryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
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
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal_ex(de.get(), plainText.get() + plainTextLength, &finalLength)) {
        qCritical() << "Couldn't finalise decryption. EVP_DecryptFinal_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    dataLength = plainTextLength + finalLength;

    QByteArray decryptedData = QByteArray(reinterpret_cast<char*>(plainText.get()), dataLength);

    return decryptedData;
}
