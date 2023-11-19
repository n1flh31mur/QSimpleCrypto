/*
 * Copyright 2023 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
 */

#ifndef QX509_H
#define QX509_H

#include "QSimpleCrypto_global.h"

#include <QMap>
#include <QObject>

#include <memory>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace QSimpleCrypto {
class QSIMPLECRYPTO_EXPORT QX509 {

#define oneYearMSecs 31536000L

///
/// \brief x509LastVersion - Last version of X509 certificate.
/// \details Version number starts from zero, so "2" is "3" version of X509 certificate.
///
#define x509LastVersion 2

public:
    QX509();

    ///
    /// \brief loadCertificateFromFile - Function load X509 from file and returns OpenSSL structure.
    /// \param filePath - File path to certificate.
    /// \return Returns OpenSSL X509 structure or nullptr, if error happened. Returned value must be cleaned up with 'X509_free' to avoid memory leak.
    ///
    [[nodiscard]] X509* loadCertificateFromFile(const QByteArray& filePath);

    ///
    /// \brief signCertificate - Function signs X509 certificate and returns signed X509 OpenSSL structure.
    /// \param endCertificate - Certificate that will be signed. Must be provided with not null X509 OpenSSL struct.
    /// \param caCertificate - CA certificate that will sign end certificate. Must be provided with not null X509 OpenSSL struct.
    /// \param caPrivateKey - CA certificate private key. Must be provided with not null EVP_PKEY OpenSSL struct.
    /// \param fileName - With that name certificate will be saved. Leave "", if certificate don't need to be saved.
    /// \return Returns OpenSSL X509 structure or nullptr, if error happened.
    ///
    [[nodiscard]] X509* signCertificate(X509* endCertificate, X509* caCertificate, EVP_PKEY* caPrivateKey, const QByteArray& fileName = "");

    ///
    /// \brief verifyCertificate - Function verifies X509 certificate and returns verified X509 OpenSSL structure.
    /// \param x509 - OpenSSL X509. That certificate will be verified. Must be provided with not null X509 OpenSSL struct.
    /// \param store - Trusted certificate must be added to X509_Store with 'addCertificateToStore(X509_STORE* ctx, X509* x509)'.
    /// \return Returns OpenSSL X509 structure or nullptr, if error happened.
    ///
    [[nodiscard]] X509* verifyCertificate(X509* x509, X509_STORE* store);

    ///
    /// \brief generateSelfSignedCertificate - Function generates and returns self signed X509 certificate.
    /// \param key - OpenSSL RSA key. Must be provided with not null EVP_PKEY OpenSSL struct.
    /// \param additionalData - Certificate information.
    /// \param certificateFileName - With that name certificate will be saved. Leave "", if don't need to save it.
    /// \param md - OpenSSL EVP_MD structure. Example: EVP_sha512().
    /// \param notBefore - X509 start date. For example "0" to start from current date.
    /// \param notAfter - X509 end date. For example "31536000L" to sign it for one year from "notBefore" date.
    /// \param serialNumber - X509 certificate serial number.
    /// \param version - X509 certificate version. Recomended to leave it with "x509LastVersion".
    /// \return Returns OpenSSL X509 structure or nullptr, if error happened. Returned value must be cleaned up with 'X509_free' to avoid memory leak.
    ///
    [[nodiscard]] X509* generateSelfSignedCertificate(EVP_PKEY* key, const QMap<QByteArray, QByteArray>& additionalData,
        const QByteArray& certificateFileName = "", const EVP_MD* md = EVP_sha512(),
        const quint64& notBefore = 0, const quint64& notAfter = oneYearMSecs,
        const quint32 serialNumber = 1, const quint8 version = x509LastVersion);
};
} // namespace QSimpleCrypto

#endif // QX509_H
