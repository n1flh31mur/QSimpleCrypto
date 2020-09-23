/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#ifndef QX509STORE_H
#define QX509STORE_H

#include "QSimpleCrypto_global.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace QSimpleCrypto
{
    class QSIMPLECRYPTO_EXPORT QX509Store {
    public:
        QX509Store();

        bool addCertificateToStore(X509_STORE* store, X509* x509);
        bool addLookup(X509_STORE* store, X509_LOOKUP_METHOD* meth);

        bool setDepth(X509_STORE* store, const int& depth);
        bool setFlag(X509_STORE* store, const unsigned long& flag);
        bool setPurpose(X509_STORE* store, const int& purpose);
        bool setTrust(X509_STORE* store, const int& trust);
        bool setDefaultPaths(X509_STORE* store);

        bool loadLocations(X509_STORE* store, const QByteArray& fileName, const QByteArray& dirPath);
        bool loadLocations(X509_STORE* store, const QFile& file);
        bool loadLocations(X509_STORE* store, const QFileInfo& fileInfo);
    };
}

#endif // QX509STORE_H
