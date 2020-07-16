#include "encrypt_aead.h"

encrypt_aead::encrypt_aead()
{
}

///
/// \brief encrypt_aead::encrypt_aes_gcm
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
QByteArray encrypt_aead::encrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
    unsigned char key[],
    unsigned char iv[], const int& iv_length,
    unsigned char aad[], const int& aad_length,
    unsigned char tag[], const int& tag_length)
{
    /* Create cipher */
    EVP_CIPHER_CTX* en;

    /* Initialise cipcher */
    if (!(en = EVP_CIPHER_CTX_new())) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int plaintext_length = data.size(), ciphertext_length;

    /* Initialise cipchertext. Here we will store encrypted data */
    unsigned char* ciphertext;
    if (!(ciphertext = reinterpret_cast<unsigned char*>(malloc(size_t(plaintext_length))))) {
        qCritical() << "Could'nt allocate memory for \'ciphertext\'.";
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(en, cipher, nullptr, key, iv)) {
        qCritical() << "Couldn't initialise encryption operation. EVP_EncryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
    */
    if (!EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_SET_IVLEN, iv_length, nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad_length > 0) {
        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_EncryptUpdate(en, nullptr, &ciphertext_length, aad, aad_length)) {
            qCritical() << "Couldn't provide aad data. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

            /* Clean up */
            EVP_CIPHER_CTX_free(en);
            free(ciphertext);

            return QByteArray();
        }
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en, ciphertext, &ciphertext_length, reinterpret_cast<const unsigned char*>(data.data()), plaintext_length)) {
        qCritical() << "Couldn't provide message to be encrypted. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
    */
    if (!EVP_EncryptFinal_ex(en, ciphertext, &plaintext_length)) {
        qCritical() << "Couldn't finalise encryption. EVP_EncryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_GCM_GET_TAG, tag_length, tag)) {
        qCritical() << "Couldn't get tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), ciphertext_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(en);
    free(ciphertext);

    return encrypted;
}

///
/// \brief encrypt_aead::decrypt_aes_gcm
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
QByteArray encrypt_aead::decrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
    unsigned char key[],
    unsigned char iv[], const int& iv_length,
    unsigned char aad[], const int& aad_length,
    unsigned char tag[], const int& tag_length)
{
    /* Create cipher */
    EVP_CIPHER_CTX* de;

    /* Initialise cipcher */
    if (!(de = EVP_CIPHER_CTX_new())) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int ciphertext_length = data.size(), plaintext_length;

    /* Initialise cipchertext. Here we will store decrypted data */
    unsigned char* plaintext;
    if (!(plaintext = reinterpret_cast<unsigned char*>(malloc(size_t(ciphertext_length))))) {
        qCritical() << "Could'nt allocate memory for \'plaintext.\'";
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(de, cipher, nullptr, key, iv)) {
        qCritical() << "Couldn't initialise decryption operation. EVP_DecryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_IVLEN, iv_length, nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad_length > 0) {
        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_DecryptUpdate(de, nullptr, &plaintext_length, aad, aad_length)) {
            qCritical() << "Couldn't provide aad data. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

            /* Clean up */
            EVP_CIPHER_CTX_free(de);
            free(plaintext);

            return QByteArray();
        }
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(de, plaintext, &plaintext_length, reinterpret_cast<const unsigned char*>(data.data()), ciphertext_length)) {
        qCritical() << "Couldn't provide message to be decrypted. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_GCM_SET_TAG, tag_length, tag)) {
        qCritical() << "Coldn't set tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal_ex(de, plaintext, &ciphertext_length)) {
        qCritical() << "Couldn't finalise decryption. EVP_DecryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plaintext), plaintext_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(de);
    free(plaintext);

    return decrypted;
}

///
/// \brief encrypt_aead::encrypt_aes_ccm
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
QByteArray encrypt_aead::encrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
    unsigned char key[],
    unsigned char iv[], const int& iv_length,
    unsigned char aad[], const int& aad_length,
    unsigned char tag[], const int& tag_length)
{
    /* Create cipher */
    EVP_CIPHER_CTX* en;

    /* Initialise cipcher */
    if (!(en = EVP_CIPHER_CTX_new())) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int plaintext_length = data.size(), ciphertext_length;

    /* Initialise cipchertext. Here we will store encrypted data */
    unsigned char* ciphertext;
    if (!(ciphertext = reinterpret_cast<unsigned char*>(malloc(size_t(plaintext_length))))) {
        qCritical() << "Could'nt allocate memory for \'ciphertext\'.";
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(en, cipher, nullptr, key, iv)) {
        qCritical() << "Couldn't initialise encryption operation. EVP_EncryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
    */
    if (!EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_IVLEN, iv_length, nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Set tag length */
    if (!EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_SET_TAG, tag_length, nullptr)) {
        qCritical() << "Coldn't set tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad_length > 0) {
        /* Provide the total plaintext length */
        if (!EVP_EncryptUpdate(en, nullptr, &ciphertext_length, nullptr, plaintext_length)) {
            qCritical() << "Couldn't provide total plaintext length. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

            /* Clean up */
            EVP_CIPHER_CTX_free(en);
            free(ciphertext);

            return QByteArray();
        }

        /*
     * Provide any AAD data. This can be called zero or more times as required
    */
        if (!EVP_EncryptUpdate(en, nullptr, &ciphertext_length, aad, aad_length)) {
            qCritical() << "Couldn't provide aad data. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

            /* Clean up */
            EVP_CIPHER_CTX_free(en);
            free(ciphertext);

            return QByteArray();
        }
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en, ciphertext, &ciphertext_length, reinterpret_cast<const unsigned char*>(data.data()), plaintext_length)) {
        qCritical() << "Could'nt provide message to be encrypted. EVP_EncryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
    */
    if (!EVP_EncryptFinal_ex(en, ciphertext, &plaintext_length)) {
        qCritical() << "Couldn't finalise encryption. EVP_EncryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Get the tag */
    if (!EVP_CIPHER_CTX_ctrl(en, EVP_CTRL_CCM_GET_TAG, tag_length, tag)) {
        qCritical() << "Couldn't get tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(en);
        free(ciphertext);

        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), ciphertext_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(en);
    free(ciphertext);

    return encrypted;
}

///
/// \brief encrypt_aead::decrypt_aes_ccm
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
QByteArray encrypt_aead::decrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
    unsigned char key[],
    unsigned char iv[], const int& iv_length,
    unsigned char aad[], const int& aad_length,
    unsigned char tag[], const int& tag_length)
{
    /* Create cipher */
    EVP_CIPHER_CTX* de;

    /* Initialise cipcher */
    if (!(de = EVP_CIPHER_CTX_new())) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Set length of data */
    int ciphertext_length = data.size(), plaintext_length;

    /* Initialise plaintext. Here we will store decrypted data */
    unsigned char* plaintext;
    if (!(plaintext = reinterpret_cast<unsigned char*>(malloc(size_t(ciphertext_length))))) {
        qCritical() << "Could'nt allocate memory for \'plaintext\'.";
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(de, cipher, nullptr, key, iv)) {
        qCritical() << "Couldn't initialise decryption operation. EVP_DecryptInit_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_IVLEN, iv_length, nullptr)) {
        qCritical() << "Couldn't set IV length. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(de, EVP_CTRL_CCM_SET_TAG, tag_length, tag)) {
        qCritical() << "Coldn't set tag. EVP_CIPHER_CTX_ctrl() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Check if we need to use aad */
    if (aad_length > 0) {
        /* Provide the total ciphertext length */
        if (!EVP_DecryptUpdate(de, nullptr, &plaintext_length, nullptr, ciphertext_length)) {
            qCritical() << "Couldn't provide total plaintext length. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

            /* Clean up */
            EVP_CIPHER_CTX_free(de);
            free(plaintext);

            return QByteArray();
        }

        /*
         * Provide any AAD data. This can be called zero or more times as required
        */
        if (!EVP_DecryptUpdate(de, nullptr, &plaintext_length, aad, aad_length)) {
            qCritical() << "Couldn't provide aad data. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

            /* Clean up */
            EVP_CIPHER_CTX_free(de);
            free(plaintext);

            return QByteArray();
        }
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(de, plaintext, &plaintext_length, reinterpret_cast<const unsigned char*>(data.data()), ciphertext_length)) {
        qCritical() << "Couldn't provide message to be decrypted. EVP_DecryptUpdate() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal_ex(de, plaintext, &ciphertext_length)) {
        qCritical() << "Couldn't finalise decryption. EVP_DecryptFinal_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        EVP_CIPHER_CTX_free(de);
        free(plaintext);

        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plaintext), plaintext_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(de);
    free(plaintext);

    return decrypted;
}
