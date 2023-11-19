/*
 * Copyright 2023 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
 */

#ifndef QX509STORE_H
#define QX509STORE_H

#include "QSimpleCrypto_global.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <memory>

#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace QSimpleCrypto {
class QSIMPLECRYPTO_EXPORT QX509Store {
public:
    QX509Store();

    ///
    /// \brief addCertificateToStore - Function adds X509 certificate to X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param x509 - OpenSSL X509 certificate that will be added to store.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool addCertificateToStore(X509_STORE* store, X509* x509);

    ///
    /// \brief addLookup - Function adds lookup method for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param method - OpenSSL X509_LOOKUP_METHOD. Example: X509_LOOKUP_file.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool addLookup(X509_STORE* store, X509_LOOKUP_METHOD* method);

    ///
    /// \brief setDepth - Function sets store for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param depth - That is the maximum number of untrusted CA certificates that can appear in a chain. Example: 0.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool setDepth(X509_STORE* store, const quint32 depth);

    ///
    /// \brief setFlag - Function sets flag for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param flag - The verification flags consists of zero or more of the following flags ored together. Example: X509_V_FLAG_CRL_CHECK.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool setFlag(X509_STORE* store, const quint32 flag);

    ///
    /// \brief setPurpose - Function sets purpose for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param purpose - Verification purpose in param to purpose. Example: X509_PURPOSE_ANY.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool setPurpose(X509_STORE* store, const quint8 purpose);

    ///
    /// \brief setTrust - Function sets trust level for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param trust - Trust Level. Example: X509_TRUST_SSL_SERVER.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool setTrust(X509_STORE* store, const quint8 trust);

    ///
    /// \brief loadStoreDefaultCertificates - Function loads certificates into the X509_STORE from the hardcoded default paths.
    /// \param store - OpenSSL X509_STORE.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool loadStoreDefaultCertificates(X509_STORE* store);

    ///
    /// \brief loadLocations - Load locations for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param fileName - File name. Example: "caCertificate.pem".
    /// \param dirPath - Path to file. Example: "root/etc".
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool loadLocations(X509_STORE* store, const QByteArray& fileName, const QByteArray& dirPath);

    ///
    /// \brief loadLocations - Load locations for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param file - Qt QFile not null object.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool loadLocations(X509_STORE* store, const QFile& file);

    ///
    /// \brief loadLocations - Load locations for X509 store.
    /// \param store - OpenSSL X509_STORE.
    /// \param fileInfo - Qt QFileInfo not null object.
    /// \return Returns 'true' on success or "false" on failure.
    ///
    bool loadLocations(X509_STORE* store, const QFileInfo& fileInfo);
};
} // namespace QSimpleCrypto

#endif // QX509STORE_H
