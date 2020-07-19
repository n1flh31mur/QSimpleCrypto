#include "RSAEncryption.h"

RSAEncryption::RSAEncryption()
{
}

///
/// \brief RSAEncryption::generate_rsa_keys
/// \param bits - key size (1024 to 4096)
/// \param rsa_bignum - The exponent is an odd number, typically 3, 17 or 65537.
/// \return returned value must be cleaned up with 'RSA_free(rsa);' to avoid memory leak
///
RSA* RSAEncryption::generate_rsa_keys(const int& bits, const int& rsa_bignum)
{
    BIGNUM* bne = BN_new();
    if (!BN_set_word(bne, rsa_bignum)) {
        qCritical() << "Couldn't generate bignum. BN_set_word() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    RSA* rsa = RSA_new();
    if (!RSA_generate_key_ex(rsa, bits, bne, nullptr)) {
        qCritical() << "Couldn't generate RSA. RSA_generate_key_ex() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    BN_free(bne);

    return rsa;
}

///
/// \brief RSAEncryption::save_rsa_publicKey
/// \param rsa - openssl RSA structure
/// \param publicKeyFileName - file name of public key file
///
void RSAEncryption::save_rsa_publicKey(const RSA* rsa, const QByteArray& publicKeyFileName)
{
    BIO* bp_public = BIO_new_file(publicKeyFileName.data(), "w+");
    if (!PEM_write_bio_RSAPublicKey(bp_public, rsa)) {
        qCritical() << "Couldn't save public key. PEM_write_bio_RSAPublicKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }
    BIO_free_all(bp_public);
}

///
/// \brief RSAEncryption::save_rsa_privateKey
/// \param rsa - openssl RSA structure
/// \param privateKeyFileName - file name of private key file
/// \param passphrase - private key password
/// \param cipher - evp cipher. Can be used with openssl evp chipers (ecb, cbc, cfb, ofb, ctr) - 128, 192, 256. Example: EVP_aes_256_ecb()
/// \param key - key of evp cipher
/// \param key_length
///
void RSAEncryption::save_rsa_privateKey(RSA* rsa, const QByteArray& privateKeyFileName, QString passphrase,
    const EVP_CIPHER* cipher, unsigned char key[], const int& key_length)
{
    BIO* bp_private = BIO_new_file(privateKeyFileName.data(), "w+");
    if (!PEM_write_bio_RSAPrivateKey(bp_private, rsa, cipher, key, key_length, nullptr, &passphrase)) {
        qCritical() << "Couldn't save private key. PEM_write_bio_RSAPrivateKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    BIO_free_all(bp_private);
}

///
/// \brief RSAEncryption::get_rsa_key - gets a key from a file
/// \param rsaKeyFilePath
/// \return
///
QByteArray RSAEncryption::get_rsa_key(const QString& rsaKeyFilePath)
{
    QFile rsaKeyFile(rsaKeyFilePath);
    if (rsaKeyFile.open(QIODevice::ReadOnly)) {
        return rsaKeyFile.readAll();
    } else {
        qCritical() << "Couldn't open public key file. QFile.open() error: " << rsaKeyFile.errorString();
    }

    return "";
}

///
/// \brief RSAEncryption::public_encrypt
/// \param plaintext - text that will be encrypted
/// \param rsa - openssl RSA structure
/// \param padding - RSA padding can be used with: RSA_PKCS1_PADDING, RSA_NO_PADDING and etc
/// \return
///
QByteArray RSAEncryption::encrypt(const int& encrypt_type, QByteArray plaintext, RSA* rsa, int padding)
{
    unsigned char* ciphertext;
    if (!(ciphertext = reinterpret_cast<unsigned char*>(malloc(size_t(RSA_size(rsa)))))) {
        qCritical() << "Couldn't allocate memory for \'ciphertext\'.";
    }

    int result = 0;

    if (encrypt_type == PUBLIC_ENCRYPT) {
        result = RSA_public_encrypt(plaintext.size(), reinterpret_cast<unsigned char*>(plaintext.data()), ciphertext, rsa, padding);
    } else if (encrypt_type == PRIVATE_ENCRYPT) {
        result = RSA_private_encrypt(plaintext.size(), reinterpret_cast<unsigned char*>(plaintext.data()), ciphertext, rsa, padding);
    }

    if (result <= -1) {
        qCritical() << "Couldn't encrypt data. Error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    const QByteArray& encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), RSA_size(rsa));

    free(ciphertext);
    return encrypted;
}

///
/// \brief RSAEncryption::private_decrypt
/// \param ciphertext - text that will be decrypted
/// \param rsa - openssl RSA structure
/// \param padding - RSA padding can be used with: RSA_PKCS1_PADDING, RSA_NO_PADDING and etc
/// \return
///
QByteArray RSAEncryption::decrypt(const int& decrypt_type, QByteArray ciphertext, RSA* rsa, int padding)
{
    unsigned char* plaintext;
    if (!(plaintext = reinterpret_cast<unsigned char*>(malloc(size_t(ciphertext.size()))))) {
        qCritical() << "Couldn't allocate memory for \'plaintext\'.";
    }

    int result = 0;

    if (decrypt_type == PUBLIC_DECRYPT) {
        result = RSA_public_decrypt(RSA_size(rsa), reinterpret_cast<unsigned char*>(ciphertext.data()), plaintext, rsa, padding);
    } else if (decrypt_type == PRIVATE_DECRYPT) {
        result = RSA_private_decrypt(RSA_size(rsa), reinterpret_cast<unsigned char*>(ciphertext.data()), plaintext, rsa, padding);
    }

    if (result <= -1) {
        qCritical() << "Couldn't decrypt data. Error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    const QByteArray& decrypted = QByteArray(reinterpret_cast<char*>(plaintext));

    free(plaintext);
    return decrypted;
}
