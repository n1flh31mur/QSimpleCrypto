#include "encrypt.h"

Encrypt::Encrypt()
{
}

///
/// \brief Encrypt::randomBytes - generate random bytes. Can be used for 'Random delta (RD)'
/// \param size - size of random bytes
/// \return
///
QByteArray Encrypt::randomBytes(const int& size)
{
    unsigned char arr[sizeof(size)];
    RAND_bytes(arr, sizeof(size));

    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

///
/// \brief Encrypt::encrypt_aes_block_cipher
/// \param chiper - can be used with openssl evp chipers (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_ecb()
/// \param md - hash algroitm (sha, md and etc). Example: EVP_sha512_256
/// \param key
/// \param iv - intilization vector
/// \param rounds - round of bytes shake
/// \param passphrase - encryption password
/// \param salt - Random Delta
/// \param data - bytes (data) that will be encrypted
/// \return
///
QByteArray Encrypt::encrypt_aes_block_cipher(const EVP_CIPHER* cipher, const EVP_MD* md,
    unsigned char key[], unsigned char iv[],
    const int& rounds, const QByteArray& passphrase,
    const QByteArray& salt, QByteArray data)
{
    /* Create and Initialise cipcher */
    EVP_CIPHER_CTX* en;

    /* Initialise cipcher */
    if (!(en = EVP_CIPHER_CTX_new())) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Get salt and set password */
    const unsigned char* m_salt = reinterpret_cast<const unsigned char*>(salt.data());
    const unsigned char* password = reinterpret_cast<const unsigned char*>(passphrase.constData());

    /* Set length of data */
    int plaintext_length = data.size();
    int ciphertext_length(plaintext_length + AES_BLOCK_SIZE);
    int final_length;

    /* Initialise cipchertext. Here we will store encrypted data */
    unsigned char* ciphertext;
    if (!(ciphertext = reinterpret_cast<unsigned char*>(malloc(size_t(ciphertext_length))))) {
        qCritical() << "Could'nt allocate memory for \'ciphertext\'.";
    }

    /* Start encryption with password based encryption routine */
    if (!EVP_BytesToKey(cipher, md, m_salt, password, passphrase.length(), rounds, key, iv)) {
        qCritical() << "Couldn't start encryption routine. EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(ciphertext);
        EVP_CIPHER_CTX_free(en);

        return QByteArray();
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(en, cipher, nullptr, key, iv)) {
        qCritical() << "Couldn't initialise encryption operation. EVP_EncryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(ciphertext);
        EVP_CIPHER_CTX_free(en);

        return QByteArray();
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (!EVP_EncryptUpdate(en, ciphertext, &ciphertext_length, reinterpret_cast<const unsigned char*>(data.data()), plaintext_length)) {
        qCritical() << "Couldn't provide message to be encrypted. EVP_EncryptUpdate() failed: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(ciphertext);
        EVP_CIPHER_CTX_free(en);

        return QByteArray();
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at this stage
    */
    if (!EVP_EncryptFinal(en, ciphertext + ciphertext_length, &final_length)) {
        qCritical() << "Couldn't finalise encryption. EVP_EncryptFinal_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(ciphertext);
        EVP_CIPHER_CTX_free(en);

        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    plaintext_length = ciphertext_length + final_length;

    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), plaintext_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(en);
    free(ciphertext);

    return encrypted;
}

///
/// \brief Encrypt::decrypt_aes_block_cipher
/// \param chiper - can be used with openssl evp chipers (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_ecb()
/// \param md - hash algroitm (sha, md and etc). Example: EVP_sha512_256
/// \param key
/// \param iv - (optional) intilization vector. If not used, it must equal to nullptr
/// \param rounds - round of bytes shake
/// \param passphrase - encryption password
/// \param salt - Random Delta
/// \param data - bytes (data) that will be encrypted
/// \return
///
QByteArray Encrypt::decrypt_aes_block_cipher(const EVP_CIPHER* cipher, const EVP_MD* md,
    unsigned char key[], unsigned char iv[],
    const int& rounds, const QByteArray& passphrase,
    const QByteArray& salt, QByteArray data)
{
    /* Create cipcher */
    EVP_CIPHER_CTX* de;

    /* Initialise cipcher */
    if (!(de = EVP_CIPHER_CTX_new())) {
        qCritical() << "Couldn't intilise evp cipher. EVP_CIPHER_CTX_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    /* Get salt and password */
    const unsigned char* m_salt = reinterpret_cast<const unsigned char*>(salt.data());
    const unsigned char* password = reinterpret_cast<const unsigned char*>(passphrase.data());

    /* Set length of data */
    int data_length = data.size();
    int plaintext_length(data_length);
    int final_length;

    /* Initialise plaintext. Here we will store decrypted data */
    unsigned char* plaintext;
    if (!(plaintext = reinterpret_cast<unsigned char*>(malloc(size_t(plaintext_length) + AES_BLOCK_SIZE)))) {
        qCritical() << "Could'nt allocate memory for \'ciphertext\'.";
    }

    /* Start encryption with password based encryption routine */
    if (!EVP_BytesToKey(cipher, md, m_salt, password, passphrase.length(), rounds, key, iv)) {
        qCritical() << "Couldn't start decryption routine. EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(plaintext);
        EVP_CIPHER_CTX_free(de);

        return QByteArray();
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(de, cipher, nullptr, key, iv)) {
        qCritical() << "Couldn't initialise decryption operation. EVP_DecryptInit_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(plaintext);
        EVP_CIPHER_CTX_free(de);

        return QByteArray();
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(de, plaintext, &plaintext_length, reinterpret_cast<const unsigned char*>(data.data()), data.size())) {
        qCritical() << "Couldn't provide message to be decrypted. EVP_DecryptUpdate() failed: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(plaintext);
        EVP_CIPHER_CTX_free(de);

        return QByteArray();
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
    */
    if (!EVP_DecryptFinal_ex(de, plaintext + plaintext_length, &final_length)) {
        qCritical() << "Couldn't finalise decryption. EVP_DecryptFinal_ex() failed: " << ERR_error_string(ERR_get_error(), nullptr);

        /* Clean up */
        free(plaintext);
        EVP_CIPHER_CTX_free(de);

        return QByteArray();
    }

    /* Finilize data to be readable with qt */
    data_length = plaintext_length + final_length;

    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plaintext), data_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(de);
    free(plaintext);

    return decrypted;
}
