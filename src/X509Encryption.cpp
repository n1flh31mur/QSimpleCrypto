/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "X509Encryption.h"

QSimpleCrypto::X509Encryption::X509Encryption()
{
}

///
/// \brief QSimpleCrypto::X509Encryption::generate_self_signed_certificate
/// \param rsa - OpenSSL RSA
/// \param additionalData - Additional data of X509 certificate. (ST, OU and another data)
/// \param keyFileName - Name of private key file. Leave "", if don't need to save it
/// \param certificateFileName - Name of certificatefile. Leave "", if don't need to save it
/// \param password - Certificate password
/// \param md - Certificate Signature Algorith. Example: EVP_sha512()
/// \param cipher - OpenSSL cipher algorithm. Example: EVP_aes_256_cbc()
/// \param key - Cipher key.
/// \param key_length - Cipher key length.
/// \param serialNumber - X509 Certificate serial number.
/// \param version - X509 Certificate version
/// \param notBefore - X509 start date
/// \param notAfter - X509 end date
/// \return - Returned value must be cleaned with X509_free()
///
X509* QSimpleCrypto::X509Encryption::generate_self_signed_certificate(const RSA* rsa, const QMap<QByteArray, QByteArray>& additionalData,
    const QByteArray& keyFileName, const QByteArray& certificateFileName, QString password,
    const EVP_MD* md, const EVP_CIPHER* cipher,
    const long& serialNumber, const long& version,
    const long& notBefore, const long& notAfter)
{
    /* Intilize X509 */
    X509* x509 = nullptr;
    if (!(x509 = X509_new())) {
        qCritical() << "Couldn't intilize x509. X509_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Intilize private key */
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> keyStore { EVP_PKEY_new(), EVP_PKEY_free };

    /* Sign rsa key */
    EVP_PKEY_assign_RSA(keyStore.get(), rsa);

    /* Set certificate serial number. */
    if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), serialNumber)) {
        qCritical() << "Couldn't set serial number. ASN1_INTEGER_set() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Set certificate version */
    if (!X509_set_version(x509, version)) {
        qCritical() << "Couldn't set version. X509_set_version() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Set certificate creation and expiration date */
    X509_gmtime_adj(X509_get_notBefore(x509), notBefore);
    X509_gmtime_adj(X509_get_notAfter(x509), notAfter);

    /* Set certificate public key */
    if (!X509_set_pubkey(x509, keyStore.get())) {
        qCritical() << "Couldn't set public key. X509_set_pubkey() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Intilize issuer name */
    X509_NAME* x509Name = X509_get_subject_name(x509);
    if (x509Name == nullptr) {
        qCritical() << "Couldn't intilize X509_NAME. X509_NAME() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Add additional data to certificate */
    QMapIterator<QByteArray, QByteArray> certificateInformationList(additionalData);
    while (certificateInformationList.hasNext()) {
        /* Read next item in list */
        certificateInformationList.next();

        /* Set additional data */
        if (!X509_NAME_add_entry_by_txt(x509Name, certificateInformationList.key().data(), MBSTRING_ASC, reinterpret_cast<const unsigned char*>(certificateInformationList.value().data()), -1, -1, 0)) {
            qCritical() << "Couldn't set additional information. X509_NAME_add_entry_by_txt() error: " << ERR_error_string(ERR_get_error(), nullptr);
        }
    }

    /* Set certificate info */
    if (!X509_set_issuer_name(x509, x509Name)) {
        qCritical() << "Couldn't set issuer name. X509_set_issuer_name() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Sign certificate */
    if (!X509_sign(x509, keyStore.get(), md)) {
        qCritical() << "Couldn't sign x509. X509_sign() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    /* Write private key file on disk. If needed */
    if (!keyFileName.isEmpty()) {
        std::unique_ptr<BIO, void (*)(BIO*)> keyFile { BIO_new_file(keyFileName.data(), "w+"), BIO_free_all };
        if (!PEM_write_bio_PrivateKey(keyFile.get(), keyStore.get(), cipher, reinterpret_cast<unsigned char*>(password.data()), password.size(), nullptr, nullptr)) {
            qCritical() << "Couldn't write key file on disk. PEM_write_bio_PrivateKey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        }
    }

    /* Write certificate file on disk. If needed */
    if (!certificateFileName.isEmpty()) {
        std::unique_ptr<BIO, void (*)(BIO*)> certFile { BIO_new_file(certificateFileName.data(), "w+"), BIO_free_all };
        if (!PEM_write_bio_X509(certFile.get(), x509)) {
            qCritical() << "Couldn't write certificate file on disk. PEM_write_bio_X509() error: " << ERR_error_string(ERR_get_error(), nullptr);
        }
    }

    return x509;
}
