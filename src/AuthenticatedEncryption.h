#ifndef ENCRYPT_AEAD_H
#define ENCRYPT_AEAD_H

#include <QDebug>
#include <QObject>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

class AuthenticatedEncryption {
public:
    AuthenticatedEncryption();

    QByteArray encrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
        unsigned char key[],
        unsigned char iv[], const int& iv_length,
        unsigned char aad[], const int& aad_length,
        unsigned char tag[], const int& tag_length);
    QByteArray decrypt_aes_gcm(const EVP_CIPHER* cipher, QByteArray data,
        unsigned char key[],
        unsigned char iv[], const int& iv_length,
        unsigned char aad[], const int& aad_length,
        unsigned char tag[], const int& tag_length);

    QByteArray encrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
        unsigned char key[],
        unsigned char iv[], const int& iv_length,
        unsigned char aad[], const int& aad_length,
        unsigned char tag[], const int& tag_length);
    QByteArray decrypt_aes_ccm(const EVP_CIPHER* cipher, QByteArray data,
        unsigned char key[],
        unsigned char iv[], const int& iv_length,
        unsigned char aad[], const int& aad_length,
        unsigned char tag[], const int& tag_length);
};

#endif // ENCRYPT_AEAD_H
