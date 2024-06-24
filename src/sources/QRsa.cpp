/*
 * Copyright 2023 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
 */

#include "include/QRsa.h"

QSimpleCrypto::QRsa::QRsa()
{
}

///
/// \brief QSimpleCrypto::QRsa::generateRsaKeys - Function generate Rsa Keys and returns them in OpenSSL structure.
/// \param bits - RSA key size. For example: 2048, 4096.
/// \param rsaBigNumber - The exponent is an odd number, typically 3, 17 or 65537.
/// \return Returns 'OpenSSL RSA structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'RSA_free()' to avoid memory leak.
///
EVP_PKEY* QSimpleCrypto::QRsa::generateRsaKeys(quint32 bits, quint32 rsaPrimeNumber)
{
    try {
        /* Initialize RSA */
        EVP_PKEY* rsaKeys = nullptr;
        EVP_PKEY_CTX* rsaKeysContext = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (!rsaKeysContext) {
            throw std::runtime_error("Couldn't initialize EVP_PKEY_CTX. EVP_PKEY_CTX_new_from_name(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Initializes a public key algorithm */
        if (!EVP_PKEY_keygen_init(rsaKeysContext)) {
            throw std::runtime_error("Couldn't initialize public key algorithm. EVP_PKEY_keygen_init(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Initialize big number */
        std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> bigNumber { BN_new(), BN_free };
        if (bigNumber == nullptr) {
            throw std::runtime_error("Couldn't initialize \'bigNumber\'. BN_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Set big number */
        if (!BN_set_word(bigNumber.get(), rsaPrimeNumber)) {
            throw std::runtime_error("Couldn't set bigNumber. BN_set_word(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Generate key pair and store it in RSA */
        OSSL_PARAM params[3];
        params[0] = OSSL_PARAM_construct_uint("bits", &bits);
        params[1] = OSSL_PARAM_construct_uint("primes", &rsaPrimeNumber);
        params[2] = OSSL_PARAM_construct_end();

        /* Set up params to RSA key context */
        if (!EVP_PKEY_CTX_set_params(rsaKeysContext, params)) {
            throw std::runtime_error("Couldn't set PKEY params. EVP_PKEY_CTX_set_params(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (!EVP_PKEY_generate(rsaKeysContext, &rsaKeys)) {
            throw std::runtime_error("Couldn't generate EVP_PKEY key. EVP_PKEY_generate(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        return rsaKeys;
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

///
/// \brief QSimpleCrypto::QRsa::savePublicKey - Saves to file RSA public key.
/// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
/// \param filePath - Public key file name.
///
void QSimpleCrypto::QRsa::savePublicKey(EVP_PKEY* key, const QByteArray& filePath)
{
    try {
        /* Initialize FILE */
        FILE* publicKeyFile = fopen(filePath, "w+");
        if (!publicKeyFile) {
            throw std::runtime_error("Couldn't initialize FILE.");
        }

        /* Write public key on file */
        if (!PEM_write_PUBKEY(publicKeyFile, key)) {
            throw std::runtime_error("Couldn't save public key. PEM_write_PUBKEY(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Close FILE to avoid memory leak */
        fflush(publicKeyFile);
        fclose(publicKeyFile);
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

///
/// \brief QSimpleCrypto::QRsa::savePrivateKey - Saves to file RSA private key.
/// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
/// \param filePath - Private key file path.
/// \param password - Private key password.
/// \param cipher - Can be used with 'OpenSSL EVP_CIPHER' (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_cbc().
///
void QSimpleCrypto::QRsa::savePrivateKey(EVP_PKEY* key, const QByteArray& fileName, QByteArray password, const EVP_CIPHER* cipher)
{
    try {
        /* Initialize FILE */
        FILE* privateKeyFile = fopen(fileName, "w+");
        if (!privateKeyFile) {
            throw std::runtime_error("Couldn't initialize FILE.");
        }

        /* Write private key to file */
        if (!PEM_write_PrivateKey(privateKeyFile, key, cipher, reinterpret_cast<unsigned char*>(password.data()), password.size(), nullptr, nullptr)) {
            throw std::runtime_error("Couldn't save private key. PEM_write_PrivateKey(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Close FILE to avoid memory leak */
        fflush(privateKeyFile);
        fclose(privateKeyFile);
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

///
/// \brief QSimpleCrypto::QRsa::getPublicKeyFromFile - Gets RSA public key from a file.
/// \param filePath - File path to public key file.
/// \return Returns 'OpenSSL EVP_PKEY structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak.
///
EVP_PKEY* QSimpleCrypto::QRsa::getPublicKeyFromFile(const QByteArray& filePath)
{
    try {
        /* Initialize read FILE */
        FILE* publicKeyFile = fopen(filePath, "r");
        if (!publicKeyFile) {
            throw std::runtime_error("Couldn't initialize FILE.");
        }

        /* Initialize EVP_PKEY */
        EVP_PKEY* keyStore = nullptr;
        if (!(keyStore = EVP_PKEY_new())) {
            throw std::runtime_error("Couldn't initialize keyStore. EVP_PKEY_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Write private key to file */
        if (!PEM_read_PUBKEY(publicKeyFile, &keyStore, nullptr, nullptr)) {
            throw std::runtime_error("Couldn't read private key. PEM_read_PUBKEY(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Close FILE to avoid memory leak */
        fclose(publicKeyFile);

        return keyStore;
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

///
/// \brief QSimpleCrypto::QRsa::getPrivateKeyFromFile - Gets RSA private key from a file.
/// \param filePath - File path to private key file.
/// \param password - Private key password.
/// \return Returns 'OpenSSL EVP_PKEY structure' or 'nullptr', if error happened. Returned value must be cleaned up with 'EVP_PKEY_free()' to avoid memory leak.
///
EVP_PKEY* QSimpleCrypto::QRsa::getPrivateKeyFromFile(const QByteArray& filePath, const QByteArray& password)
{
    try {
        /* Initialize read FILE */
        FILE* privateKeyFile = fopen(filePath, "r");
        if (!privateKeyFile) {
            throw std::runtime_error("Couldn't initialize FILE.");
        }

        /* Initialize EVP_PKEY */
        EVP_PKEY* keyStore = nullptr;
        if (!(keyStore = EVP_PKEY_new())) {
            throw std::runtime_error("Couldn't initialize keyStore. EVP_PKEY_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Write private key to file */
        if (!PEM_read_PrivateKey(privateKeyFile, &keyStore, nullptr, static_cast<void*>(const_cast<char*>(password.data())))) { /// FIXME: Couldn't read private key. PEM_read_bio_PrivateKey(). Error: error:1E08010C:DECODER routines::unsupported
            throw std::runtime_error("Couldn't read private key. PEM_read_PrivateKey(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Close FILE to avoid memory leak */
        fclose(privateKeyFile);

        return keyStore;
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

///
/// \brief QSimpleCrypto::QRsa::encrypt - Encrypt data with RSA algorithm.
/// \param plaintext - Text that must be encrypted.
/// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
/// \param padding - OpenSSL RSA padding can be used with: 'RSA_PKCS1_PADDING', 'RSA_NO_PADDING' and etc.
/// \return Returns encrypted data on success or "" on failure.
///
QByteArray QSimpleCrypto::QRsa::encrypt(QByteArray plainText, EVP_PKEY* key, const quint16 padding)
{
    try {
        /* Initialize CTX for 'key' */
        EVP_PKEY_CTX* rsaKeyContext = EVP_PKEY_CTX_new(key, nullptr);
        if (!rsaKeyContext) {
            throw std::runtime_error("Couldn't initialize EVP_PKEY_CTX. EVP_PKEY_CTX_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Initialize encrypt operation for RSA */
        if (!EVP_PKEY_encrypt_init(rsaKeyContext)) {
            throw std::runtime_error("Couldn't initialize encrypt operation. EVP_PKEY_encrypt_init(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Set RSA padding for encryption */
        if (!EVP_PKEY_CTX_set_rsa_padding(rsaKeyContext, padding)) {
            throw std::runtime_error("Couldn't set RSA padding for encrypt operation. EVP_PKEY_CTX_set_rsa_padding(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Write the data into a variable to avoid additional conversion during encryption */
        unsigned char* plainData = reinterpret_cast<unsigned char*>(plainText.data());

        /* Determine encrypted buffer length */
        std::size_t encryptedDataLength;

        if (!EVP_PKEY_encrypt(rsaKeyContext, nullptr, &encryptedDataLength, plainData, plainText.size())) {
            throw std::runtime_error("Couldn't determine encrypted buffer length. EVP_PKEY_encrypt(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Initialize array. Here encrypted data will be saved */
        std::unique_ptr<unsigned char[]> cipherText { new unsigned char[encryptedDataLength]() };
        if (!cipherText) {
            throw std::runtime_error("Couldn't allocate memory for 'cipherText'.");
        }

        /* Encrypt actual data */
        if (!EVP_PKEY_encrypt(rsaKeyContext, cipherText.get(), &encryptedDataLength, plainData, plainText.size())) {
            throw std::runtime_error("Couldn't encrypt data. EVP_PKEY_encrypt(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        return QByteArray(reinterpret_cast<char*>(cipherText.get()), encryptedDataLength);
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

///
/// \brief QSimpleCrypto::QRsa::decrypt - Decrypt data with RSA algorithm.
/// \param cipherText - Text that must be decrypted.
/// \param key - RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
/// \param padding  - RSA padding can be used with: 'RSA_PKCS1_PADDING', 'RSA_NO_PADDING' and etc.
/// \return Returns encrypted data on success or "" on failure.
///
QByteArray QSimpleCrypto::QRsa::decrypt(QByteArray cipherText, EVP_PKEY* key, const quint16 padding)
{
    try {
        /* Initialize CTX for 'key' */
        EVP_PKEY_CTX* rsaKeyContext = EVP_PKEY_CTX_new(key, nullptr);
        if (!rsaKeyContext) {
            throw std::runtime_error("Couldn't initialize EVP_PKEY_CTX. EVP_PKEY_CTX_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Initialize encrypt operation for RSA */
        if (!EVP_PKEY_decrypt_init(rsaKeyContext)) {
            throw std::runtime_error("Couldn't initialize encrypt operation. EVP_PKEY_encrypt_init(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Set RSA padding for encryption */
        if (!EVP_PKEY_CTX_set_rsa_padding(rsaKeyContext, padding)) {
            throw std::runtime_error("Couldn't set RSA padding for encrypt operation. EVP_PKEY_CTX_set_rsa_padding(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Write the data into a variable to avoid additional conversion during decryption */
        unsigned char* cipherTextData = reinterpret_cast<unsigned char*>(cipherText.data());

        /* Determine decrypted buffer length */
        std::size_t decryptedDataLength;

        if (!EVP_PKEY_decrypt(rsaKeyContext, nullptr, &decryptedDataLength, cipherTextData, cipherText.size())) {
            throw std::runtime_error("Couldn't determine decrypted buffer length. EVP_PKEY_encrypt(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Initialize array. Here encrypted data will be saved */
        std::unique_ptr<unsigned char[]> plainText { new unsigned char[decryptedDataLength]() };
        if (!plainText) {
            throw std::runtime_error("Couldn't allocate memory for 'plainText'.");
        }

        /* Encrypt actual data */
        if (!EVP_PKEY_decrypt(rsaKeyContext, plainText.get(), &decryptedDataLength, cipherTextData, cipherText.size())) {
            throw std::runtime_error("Couldn't encrypt data. EVP_PKEY_encrypt(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        return QByteArray(reinterpret_cast<char*>(plainText.get()), decryptedDataLength);
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

QByteArray QSimpleCrypto::QRsa::savePrivateKeyToByteArray(EVP_PKEY* key, QByteArray password, const EVP_CIPHER* cipher)
{
    QByteArray privateKeyData;

    try {
        /* Create a memory BIO */
        BIO* mem = BIO_new(BIO_s_mem());
        if (!mem) {
            throw std::runtime_error("Couldn't create BIO.");
        }

        /* Write private key to BIO */
        if (!PEM_write_bio_PrivateKey(mem, key, cipher, reinterpret_cast<unsigned char*>(password.data()), password.size(), nullptr, nullptr)) {
            BIO_free(mem);
            throw std::runtime_error("Couldn't save private key. PEM_write_bio_PrivateKey(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Get the data from the BIO */
        BUF_MEM* memPtr;
        BIO_get_mem_ptr(mem, &memPtr);
        privateKeyData = QByteArray(memPtr->data, memPtr->length);

        /* Clean up BIO */
        BIO_free(mem);
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }

    return privateKeyData;
}

QByteArray QSimpleCrypto::QRsa::savePublicKeyToByteArray(EVP_PKEY* key)
{
    QByteArray publicKeyData;

    try {
        /* Create a memory BIO */
        BIO* mem = BIO_new(BIO_s_mem());
        if (!mem) {
            throw std::runtime_error("Couldn't create BIO.");
        }

        /* Write public key to BIO */
        if (!PEM_write_bio_PUBKEY(mem, key)) {
            BIO_free(mem);
            throw std::runtime_error("Couldn't save public key. PEM_write_bio_PUBKEY(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Get the data from the BIO */
        BUF_MEM* memPtr;
        BIO_get_mem_ptr(mem, &memPtr);
        publicKeyData = QByteArray(memPtr->data, memPtr->length);

        /* Clean up BIO */
        BIO_free(mem);
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }

    return publicKeyData;
}

EVP_PKEY* QSimpleCrypto::QRsa::getPublicKeyFromByteArray(const QByteArray& publicKeyData)
{
    try {
        /* Initialize memory BIO */
        BIO* mem = BIO_new_mem_buf(publicKeyData.data(), publicKeyData.size());
        if (!mem) {
            throw std::runtime_error("Couldn't create BIO.");
        }

        /* Initialize EVP_PKEY */
        EVP_PKEY* keyStore = nullptr;
        if (!(keyStore = EVP_PKEY_new())) {
            BIO_free(mem);
            throw std::runtime_error("Couldn't initialize keyStore. EVP_PKEY_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Read public key from BIO */
        if (!PEM_read_bio_PUBKEY(mem, &keyStore, nullptr, nullptr)) {
            BIO_free(mem);
            EVP_PKEY_free(keyStore);
            throw std::runtime_error("Couldn't read public key. PEM_read_bio_PUBKEY(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Clean up BIO */
        BIO_free(mem);

        return keyStore;
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}

EVP_PKEY* QSimpleCrypto::QRsa::getPrivateKeyFromByteArray(const QByteArray& privateKeyData, const QByteArray& password)
{
    try {
        /* Initialize memory BIO */
        BIO* mem = BIO_new_mem_buf(privateKeyData.data(), privateKeyData.size());
        if (!mem) {
            throw std::runtime_error("Couldn't create BIO.");
        }

        /* Initialize EVP_PKEY */
        EVP_PKEY* keyStore = nullptr;
        if (!(keyStore = EVP_PKEY_new())) {
            BIO_free(mem);
            throw std::runtime_error("Couldn't initialize keyStore. EVP_PKEY_new(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Read public key from BIO */
        if (!PEM_read_bio_PrivateKey(mem, &keyStore, nullptr, static_cast<void*>(const_cast<char*>(password.data())))) {
            BIO_free(mem);
            EVP_PKEY_free(keyStore);
            throw std::runtime_error("Couldn't read public key. PEM_read_bio_PrivateKey(). Error: " + QByteArray(ERR_error_string(ERR_get_error(), nullptr)));
        }

        /* Clean up BIO */
        BIO_free(mem);

        return keyStore;
    } catch (const std::exception& exception) {
        std::throw_with_nested(exception);
    } catch (...) {
        throw;
    }
}
