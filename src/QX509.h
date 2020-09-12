/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QX509_H
#define QX509_H

#include <QDebug>
#include <QMap>
#include <QObject>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace QSimpleCrypto
{
    class QX509 {
    public:
        QX509();

        X509 *validateCertificate(X509* x509, X509_STORE* store);

        X509* loadCertificateFromFile(const QByteArray& fileName);
        X509* signCertificate(X509* endCertificate, X509* caCertificate, EVP_PKEY* caPrivateKey, const QByteArray& fileName = "");

        X509* generateSelfSignedCertificate(const RSA* rsa, const QMap<QByteArray, QByteArray>& additionalData,
            const QByteArray& certificateFileName = "", const EVP_MD* md = EVP_sha512(),
            const long& serialNumber = 1, const long& version = 2,
            const long& notBefore = 0, const long& notAfter = 31536000L);
    };
} // namespace QSimpleCrypto

#endif // QX509_H
