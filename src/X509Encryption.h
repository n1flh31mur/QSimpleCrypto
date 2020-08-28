/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef X509Encryption_H
#define X509Encryption_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <QDebug>
#include <QMap>
#include <QObject>

namespace QSimpleCrypto
{
    class X509Encryption {
    public:
        X509Encryption();

        X509* generateSelfSignedCertificate(const RSA* rsa, const QMap<QByteArray, QByteArray>& additionalData,
            const QByteArray& certificateFileName = "", const EVP_MD* md = EVP_sha512(),
            const long& serialNumber = 1, const long& version = 2,
            const long& notBefore = 0, const long& notAfter = 31536000L);
    };
} // namespace QSimpleCrypto

#endif // X509Encryption_H
