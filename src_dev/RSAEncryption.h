#ifndef ENCRYPT_RSA_H
#define ENCRYPT_RSA_H

#include <QDebug>
#include <QObject>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class RSAEncryption {

#define PUBLIC_ENCRYPT 0
#define PRIVATE_ENCRYPT 1
#define PUBLIC_DECRYPT 0
#define PRIVATE_DECRYPT 1

public:
    RSAEncryption();

    RSA* generate_rsa_keys(const int& bits, const int& rsa_bignum);

    void save_rsa_publicKey(const RSA* rsa, const QByteArray& publicKeyFileName);
    void save_rsa_privateKey(RSA* rsa, const QByteArray& privateKeyFileName, QString passphrase,
        const EVP_CIPHER* cipher, unsigned char key[], const int& key_length);

    QByteArray encrypt(const bool& encrypt_type, QByteArray plaintext, RSA* key, int padding);
    QByteArray decrypt(const bool& decrypt_type, QByteArray ciphertext, RSA* key, int padding);
};

#endif // ENCRYPT_RSA_H
