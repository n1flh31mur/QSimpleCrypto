/**
 * Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QX509_H
#define QX509_H

#include "QSimpleCrypto_global.h"

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
    class QSIMPLECRYPTO_EXPORT QX509 {

    #define oneYear 31536000L
    #define x509LastVersion 2

    public:
        QX509();

        X509* loadCertificateFromFile(const QByteArray& fileName);
        X509* signCertificate(X509* endCertificate, X509* caCertificate, EVP_PKEY* caPrivateKey, const QByteArray& fileName = "");
        X509* verifyCertificate(X509* x509, X509_STORE* store);

        X509* generateSelfSignedCertificate(const RSA* rsa, const QMap<QByteArray, QByteArray>& additionalData,
            const QByteArray& certificateFileName = "", const EVP_MD* md = EVP_sha512(),
            const long& serialNumber = 1, const long& version = x509LastVersion,
            const long& notBefore = 0, const long& notAfter = oneYear);
    };
} // namespace QSimpleCrypto

#endif // QX509_H
