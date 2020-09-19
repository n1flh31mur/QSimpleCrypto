/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "QX509.h"

QSimpleCrypto::QX509::QX509()
{
}

/////
///// \brief QSimpleCrypto::QX509::loadCertificateFromFile
///// \param fileName
///// \return
/////
X509* QSimpleCrypto::QX509::loadCertificateFromFile(const QByteArray& fileName)
{
    /* Initialize X509 */
    X509* x509 = nullptr;
    if (!(x509 = X509_new())) {
        qCritical() << "Couldn't initialize X509. X509_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Initialize BIO */
    std::unique_ptr<BIO, void (*)(BIO*)> certFile { BIO_new_file(fileName.data(), "r+"), BIO_free_all };

    /* Read file */
    if (!PEM_read_bio_X509(certFile.get(), &x509, nullptr, nullptr)) {
        qCritical() << "Couldn't read certificate file from disk. PEM_read_bio_X509() error: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    return x509;
}

///
/// \brief QSimpleCrypto::QX509::signCertificate
/// \param endCertificate - certificate that will be signed
/// \param caCertificate - certificate that will sign
/// \param fileName - name of end certificate file that will be saved. Leave "", if don't need to save it
/// \return
///
X509* QSimpleCrypto::QX509::signCertificate(X509* endCertificate, X509* caCertificate, EVP_PKEY* caPrivateKey, const QByteArray& fileName)
{
    /* Set issuer to CA's subject. */
    if (!X509_set_issuer_name(endCertificate, X509_get_subject_name(caCertificate))) {
        qCritical() << "Couldn't set issuer name for X509. X509_set_issuer_name() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Sign the certificate with key. */
    if (!X509_sign(endCertificate, caPrivateKey, EVP_sha256())) {
        qCritical() << "Couldn't sign X509. X509_sign() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Write certificate file on disk. If needed */
    if (!fileName.isEmpty()) {
        /* Initialize BIO */
        std::unique_ptr<BIO, void (*)(BIO*)> certFile { BIO_new_file(fileName.data(), "w+"), BIO_free_all };

        /* Write file on disk */
        if (!PEM_write_bio_X509(certFile.get(), endCertificate)) {
            qCritical() << "Couldn't write certificate file on disk. PEM_write_bio_X509() error: " << ERR_error_string(ERR_get_error(), nullptr);
        }
    }

    return endCertificate;
}

///
/// \brief QSimpleCrypto::QX509::validateCertificate
/// \param x509 - OpenSSL X509
/// \param store - trusted certificate must be added to X509_Store with 'addCertificateToStore(X509_STORE* ctx, X509* x509)'
/// \return
///
X509* QSimpleCrypto::QX509::validateCertificate(X509* x509, X509_STORE* store)
{
    /* Initialize X509_STORE_CTX */
    std::unique_ptr<X509_STORE_CTX, void (*)(X509_STORE_CTX*)> ctx { X509_STORE_CTX_new(), X509_STORE_CTX_free };
    if (ctx == nullptr) {
        qCritical() << "Couldn't initialize keyStore. EVP_PKEY_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Set up CTX for a subsequent verification operation */
    X509_STORE_CTX_init(ctx.get(), store, x509, nullptr);

    /* Verify X509 */
    if (!X509_verify_cert(ctx.get())) {
        qCritical() << "Couldn't initialize X509. X509_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    return x509;
}

///
/// \brief QSimpleCrypto::QX509::generateSelfSignedCertificate
/// \param rsa - OpenSSL RSA
/// \param additionalData - additional data of X509 certificate. (ST, OU and another data)
/// \param certificateFileName - name of certificate file. Leave "", if don't need to save it
/// \param md - Certificate Signature Algorith. Example: EVP_sha512()
/// \param serialNumber - X509 Certificate serial number.
/// \param version - X509 Certificate version
/// \param notBefore - X509 start date
/// \param notAfter - X509 end date
/// \return - returned value must be cleaned with X509_free()
///
X509* QSimpleCrypto::QX509::generateSelfSignedCertificate(const RSA* rsa, const QMap<QByteArray, QByteArray>& additionalData,
    const QByteArray& certificateFileName, const EVP_MD* md,
    const long& serialNumber, const long& version,
    const long& notBefore, const long& notAfter)
{
    /* Initialize X509 */
    X509* x509 = nullptr;
    if (!(x509 = X509_new())) {
        qCritical() << "Couldn't initialize X509. X509_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Initialize EVP_PKEY */
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> keyStore { EVP_PKEY_new(), EVP_PKEY_free };
    if (keyStore == nullptr) {
        qCritical() << "Couldn't initialize keyStore. EVP_PKEY_new() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Sign rsa key */
    if (!EVP_PKEY_assign_RSA(keyStore.get(), rsa)) {
        qCritical() << "Couldn't assign rsa. EVP_PKEY_assign_RSA() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Set certificate serial number. */
    if (!ASN1_INTEGER_set(X509_get_serialNumber(x509), serialNumber)) {
        qCritical() << "Couldn't set serial number. ASN1_INTEGER_set() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Set certificate version */
    if (!X509_set_version(x509, version)) {
        qCritical() << "Couldn't set version. X509_set_version() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Set certificate creation and expiration date */
    X509_gmtime_adj(X509_get_notBefore(x509), notBefore);
    X509_gmtime_adj(X509_get_notAfter(x509), notAfter);

    /* Set certificate public key */
    if (!X509_set_pubkey(x509, keyStore.get())) {
        qCritical() << "Couldn't set public key. X509_set_pubkey() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Initialize X509_NAME */
    X509_NAME* x509Name = X509_get_subject_name(x509);
    if (x509Name == nullptr) {
        qCritical() << "Couldn't initialize X509_NAME. X509_NAME() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Add additional data to certificate */
    QMapIterator<QByteArray, QByteArray> certificateInformationList(additionalData);
    while (certificateInformationList.hasNext()) {
        /* Read next item in list */
        certificateInformationList.next();

        /* Set additional data */
        if (!X509_NAME_add_entry_by_txt(x509Name, certificateInformationList.key().data(), MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(certificateInformationList.value().data()), -1, -1, 0)) {
            qCritical() << "Couldn't set additional information. X509_NAME_add_entry_by_txt() error: " << ERR_error_string(ERR_get_error(), nullptr);
        }
    }

    /* Set certificate info */
    if (!X509_set_issuer_name(x509, x509Name)) {
        qCritical() << "Couldn't set issuer name. X509_set_issuer_name() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Sign certificate */
    if (!X509_sign(x509, keyStore.get(), md)) {
        qCritical() << "Couldn't sign X509. X509_sign() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
    }

    /* Write certificate file on disk. If needed */
    if (!certificateFileName.isEmpty()) {
        /* Initialize BIO */
        std::unique_ptr<BIO, void (*)(BIO*)> certFile { BIO_new_file(certificateFileName.data(), "w+"), BIO_free_all };

        /* Write file on disk */
        if (!PEM_write_bio_X509(certFile.get(), x509)) {
            qCritical() << "Couldn't write certificate file on disk. PEM_write_bio_X509() error: " << ERR_error_string(ERR_get_error(), nullptr);
        }
    }

    return x509;
}
