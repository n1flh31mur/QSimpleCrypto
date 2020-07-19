#ifndef ENCRYPT_RSA_H
#define ENCRYPT_RSA_H

#include <QDebug>
#include <QFile>
#include <QObject>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class RSAEncryption {

#define PUBLIC_ENCRYPT 0
#define PRIVATE_ENCRYPT 1
#define PUBLIC_DECRYPT 2
#define PRIVATE_DECRYPT 3

public:
    RSAEncryption();

    RSA* generate_rsa_keys(const int& bits, const int& rsa_bignum);

    void save_rsa_publicKey(const RSA* rsa, const QByteArray& publicKeyFileName);
    void save_rsa_privateKey(RSA* rsa, const QByteArray& privateKeyFileName, QString passphrase,
        const EVP_CIPHER* cipher, unsigned char key[], const int& key_length);

    QByteArray get_rsa_key(const QString& rsaKeyFilePath);

    QByteArray encrypt(const int& encrypt_type, QByteArray plaintext, RSA* rsa, int padding);
    QByteArray decrypt(const int& decrypt_type, QByteArray ciphertext, RSA* rsa, int padding);
};

#endif // ENCRYPT_RSA_H
