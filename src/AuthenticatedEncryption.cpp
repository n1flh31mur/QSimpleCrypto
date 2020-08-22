/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "AuthenticatedEncryption.h"

QSimpleCrypto::AuthenticatedEncryption::AuthenticatedEncryption()
{
}

///
/// \brief AuthenticatedEncryption::encrypt_aes_gcm
/// \param cipher - can be used with openssl evp chipers (gcm) - 128, 192, 256. Example: EVP_aes_256_gcm()
/// \param data - bytes (data) that will be encrypted
/// \param key
/// \param iv - intilization vector
/// \param iv_length
/// \param aad - (optional) additional authenticated data. If not used, it must equal to nullptr
/// \param aad_length - (optional) If not used, it must equal to 0
/// \param tag
/// \param tag_length
/// \return
///
QByteArray QSimpleCrypto::AuthenticatedEncryption::encrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
    QByteArray key, QByteArray iv,
    QByteArray aad, QByteArray* tag)
{
    /* Create cipher */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> en { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };

    /* Initialise cipcher */
    if (en == nullptr) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int plainText_length = data.size();
    int cipherText_length = 0;

    /* Initialise cipchertext. Here we will store encrypted data */
    std::unique_ptr<unsigned char[]> ciphertext { new unsigned char[plainText_length]() };
    if (ciphertext == nullptr) {
        qCritical() << "Couldn't allocate memory for \'ciphertext\'.";
        return QByteArray();
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(en.get(), cipher, nullptr, reinterpret_cast<unsigned char*>(key.data()), reinterpret_cast<unsigned char*>(iv.data()))) {
        qCritical() << "Couldn't initialise encryption operation. EVP_EncryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
    */
    if (!EVP_CIPHER_CTX_ctrl(en.get(), EVP_CTRL_GCM_SET_IVLEN, iv.length(), nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad.length() > 0) {
        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_EncryptUpdate(en.get(), nullptr, &cipherText_length, reinterpret_cast<unsigned char*>(aad.data()), aad.length())) {
            qCritical() << "Couldn't provide aad data. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
            return QByteArray();
        }
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en.get(), ciphertext.get(), &cipherText_length, reinterpret_cast<const unsigned char*>(data.data()), plainText_length)) {
        qCritical() << "Couldn't provide message to be encrypted. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
    */
    if (!EVP_EncryptFinal_ex(en.get(), ciphertext.get(), &plainText_length)) {
        qCritical() << "Couldn't finalise encryption. EVP_EncryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(en.get(), EVP_CTRL_GCM_GET_TAG, tag->length(), reinterpret_cast<unsigned char*>(tag->data()))) {
        qCritical() << "Couldn't get tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext.get()), cipherText_length);

    return encrypted;
}

///
/// \brief AuthenticatedEncryption::decrypt_aes_gcm
/// \param cipher - can be used with openssl evp chipers (gcm) - 128, 192, 256. Example: EVP_aes_256_gcm()
/// \param data - bytes (data) that will be encrypted
/// \param key
/// \param iv - intilization vector
/// \param iv_length
/// \param aad - (optional) additional authenticated data. If not used, it must equal to nullptr
/// \param aad_length - (optional) If not used, it must equal to 0
/// \param tag
/// \param tag_length
/// \return
///
QByteArray QSimpleCrypto::AuthenticatedEncryption::decrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
    QByteArray key, QByteArray iv,
    QByteArray aad, QByteArray* tag)
{
    /* Create cipher */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> de { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };

    /* Initialise cipcher */
    if (de.get() == nullptr) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int cipherText_length = data.size();
    int plainText_length = 0;

    /* Initialise cipchertext. Here we will store decrypted data */
    std::unique_ptr<unsigned char[]> plainText { new unsigned char[cipherText_length]() };
    if (plainText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'plaintext.\'";
        return QByteArray();
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(de.get(), cipher, nullptr, reinterpret_cast<unsigned char*>(key.data()), reinterpret_cast<unsigned char*>(iv.data()))) {
        qCritical() << "Couldn't initialise decryption operation. EVP_DecryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(de.get(), EVP_CTRL_GCM_SET_IVLEN, iv.length(), nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad.length() > 0) {
        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_DecryptUpdate(de.get(), nullptr, &plainText_length, reinterpret_cast<unsigned char*>(aad.data()), aad.length())) {
            qCritical() << "Couldn't provide aad data. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
            return QByteArray();
        }
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(de.get(), plainText.get(), &plainText_length, reinterpret_cast<const unsigned char*>(data.data()), cipherText_length)) {
        qCritical() << "Couldn't provide message to be decrypted. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(de.get(), EVP_CTRL_GCM_SET_TAG, tag->length(), reinterpret_cast<unsigned char*>(tag->data()))) {
        qCritical() << "Coldn't set tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal_ex(de.get(), plainText.get(), &cipherText_length)) {
        qCritical() << "Couldn't finalise decryption. EVP_DecryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plainText.get()), plainText_length);

    return decrypted;
}

///
/// \brief AuthenticatedEncryption::encrypt_aes_ccm
/// \param cipher - can be used with openssl evp chipers (ccm) - 128, 192, 256. Example: EVP_aes_256_ccm()
/// \param data - bytes (data) that will be encrypted
/// \param key
/// \param iv - intilization vector
/// \param iv_length
/// \param aad - (optional) additional authenticated data. If not used, it must equal to nullptr
/// \param aad_length - (optional) If not used, it must equal to 0
/// \param tag
/// \param tag_length
/// \return
///
QByteArray QSimpleCrypto::AuthenticatedEncryption::encrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
    QByteArray key, QByteArray iv,
    QByteArray aad, QByteArray* tag)
{
    /* Initialise cipcher */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> en { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
    if (en == nullptr) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int plainText_length = data.size();
    int cipherText_length = 0;

    /* Initialise cipchertext. Here we will store encrypted data */
    std::unique_ptr<unsigned char[]> cipherText { new unsigned char[plainText_length]() };
    if (cipherText.get() == nullptr) {
        qCritical() << "Couldn't allocate memory for \'ciphertext\'.";
        return QByteArray();
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(en.get(), cipher, nullptr, reinterpret_cast<unsigned char*>(key.data()), reinterpret_cast<unsigned char*>(iv.data()))) {
        qCritical() << "Couldn't initialise encryption operation. EVP_EncryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
    */
    if (!EVP_CIPHER_CTX_ctrl(en.get(), EVP_CTRL_CCM_SET_IVLEN, iv.length(), nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set tag length */
    if (!EVP_CIPHER_CTX_ctrl(en.get(), EVP_CTRL_CCM_SET_TAG, tag->length(), nullptr)) {
        qCritical() << "Coldn't set tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad.length() > 0) {
        /* Provide the total plaintext length */
        if (!EVP_EncryptUpdate(en.get(), nullptr, &cipherText_length, nullptr, plainText_length)) {
            qCritical() << "Couldn't provide total plaintext length. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
            return QByteArray();
        }

        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_EncryptUpdate(en.get(), nullptr, &cipherText_length, reinterpret_cast<unsigned char*>(aad.data()), aad.length())) {
            qCritical() << "Couldn't provide aad data. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
            return QByteArray();
        }
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en.get(), cipherText.get(), &cipherText_length, reinterpret_cast<const unsigned char*>(data.data()), plainText_length)) {
        qCritical() << "Couldn't provide message to be encrypted. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
    */
    if (!EVP_EncryptFinal_ex(en.get(), cipherText.get(), &plainText_length)) {
        qCritical() << "Couldn't finalise encryption. EVP_EncryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(en.get(), EVP_CTRL_CCM_GET_TAG, tag->length(), reinterpret_cast<unsigned char*>(tag->data()))) {
        qCritical() << "Couldn't get tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(cipherText.get()), cipherText_length);

    return encrypted;
}

///
/// \brief AuthenticatedEncryption::decrypt_aes_ccm
/// \param cipher - can be used with openssl evp chipers (ccm) - 128, 192, 256. Example: EVP_aes_256_ccm()
/// \param data - bytes (data) that will be encrypted
/// \param key
/// \param iv - intilization vector
/// \param iv_length
/// \param aad - (optional) additional authenticated data. If not used, it must equal to nullptr
/// \param aad_length - (optional) If not used, it must equal to 0
/// \param tag
/// \param tag_length
/// \return
///
QByteArray QSimpleCrypto::AuthenticatedEncryption::decrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
    QByteArray key, QByteArray iv,
    QByteArray aad, QByteArray* tag)
{
    /* Initialise cipcher */
    std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> de { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };

    if (de.get() == nullptr) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int cipherText_length = data.size();
    int plainText_length = 0;

    /* Initialise plaintext. Here we will store decrypted data */
    std::unique_ptr<unsigned char[]> plainText { new unsigned char[cipherText_length]() };
    if (plainText == nullptr) {
        qCritical() << "Couldn't allocate memory for \'plaintext\'.";
        return QByteArray();
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(de.get(), cipher, nullptr, reinterpret_cast<unsigned char*>(key.data()), reinterpret_cast<unsigned char*>(iv.data()))) {
        qCritical() << "Couldn't initialise decryption operation. EVP_DecryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(de.get(), EVP_CTRL_CCM_SET_IVLEN, iv.length(), nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(de.get(), EVP_CTRL_CCM_SET_TAG, tag->length(), reinterpret_cast<unsigned char*>(tag->data()))) {
        qCritical() << "Coldn't set tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad.length() > 0) {
        /* Provide the total ciphertext length */
        if (!EVP_DecryptUpdate(de.get(), nullptr, &plainText_length, nullptr, cipherText_length)) {
            qCritical() << "Couldn't provide total plaintext length. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
            return QByteArray();
        }

        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_DecryptUpdate(de.get(), nullptr, &plainText_length, reinterpret_cast<unsigned char*>(aad.data()), aad.length())) {
            qCritical() << "Couldn't provide aad data. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
            return QByteArray();
        }
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(de.get(), plainText.get(), &plainText_length, reinterpret_cast<const unsigned char*>(data.data()), cipherText_length)) {
        qCritical() << "Couldn't provide message to be decrypted. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal_ex(de.get(), plainText.get(), &cipherText_length)) {
        qCritical() << "Couldn't finalise decryption. EVP_DecryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plainText.get()), plainText_length);

    return decrypted;
}
