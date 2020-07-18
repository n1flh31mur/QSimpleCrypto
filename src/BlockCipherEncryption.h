#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <QDebug>
#include <QObject>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

class BlockCipherEncryption {
public:
    BlockCipherEncryption();
    QByteArray generate_random_bytes(const int& size);

    QByteArray encrypt_aes_block_cipher(const EVP_CIPHER* cipher, const EVP_MD* md,
        unsigned char key[], unsigned char iv[],
        const int& rounds, const QByteArray& passphrase,
        const QByteArray& salt, QByteArray data);
    QByteArray decrypt_aes_block_cipher(const EVP_CIPHER* cipher, const EVP_MD* md,
        unsigned char key[], unsigned char iv[],
        const int& rounds, const QByteArray& passphrase,
        const QByteArray& salt, QByteArray data);
};

#endif // ENCRYPT_H
