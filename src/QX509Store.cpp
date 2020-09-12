/**
 * Copyright Copyright 2020 BrutalWizard (https://github.com/bru74lw1z4rd). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution
**/

#include "QX509Store.h"

QSimpleCrypto::QX509Store::QX509Store()
{
}

///
/// \brief QSimpleCrypto::QX509::addCertificateToStore
/// \param ctx - OpenSSL X509_STORE
/// \param x509 - OpenSSL X509
/// \return
///
bool QSimpleCrypto::QX509Store::addCertificateToStore(X509_STORE* ctx, X509* x509)
{
    if (!X509_STORE_add_cert(ctx, x509)) {
        qCritical() << "Couldn't add certificate to X509_STORE. X509_STORE_add_cert() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setCertificateDepth
/// \param ctx - OpenSSL X509_STORE
/// \param depth - Sets the maximum verification depth to depth. That is the maximum number of untrusted CA certificates that can appear in a chain. Example: 0
/// \return
///
bool QSimpleCrypto::QX509Store::setDepth(X509_STORE* ctx, const int& depth)
{
    if (!X509_STORE_set_depth(ctx, depth)) {
        qCritical() << "Couldn't set depth for X509_STORE. X509_STORE_set_depth() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setFlag
/// \param ctx - OpenSSL X509_STORE
/// \param flag - The verification flags consists of zero or more of the following flags ored together. Example: X509_V_FLAG_CRL_CHECK
/// \return
///
bool QSimpleCrypto::QX509Store::setFlag(X509_STORE* ctx, const unsigned long& flag)
{
    if (!X509_STORE_set_flags(ctx, flag)) {
        qCritical() << "Couldn't set flag for X509_STORE. X509_STORE_set_flags() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setFlag
/// \param ctx - OpenSSL X509_STORE
/// \param purpose - Verification purpose in param to purpose. Example: X509_PURPOSE_ANY
/// \return
///
bool QSimpleCrypto::QX509Store::setPurpose(X509_STORE* ctx, const int& purpose)
{
    if (!X509_STORE_set_purpose(ctx, purpose)) {
        qCritical() << "Couldn't set purpose for X509_STORE. X509_STORE_set_purpose() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setTrust
/// \param ctx - OpenSSL X509_STORE
/// \param trust - Trust Level. Example: X509_TRUST_SSL_SERVER
/// \return
///
bool QSimpleCrypto::QX509Store::setTrust(X509_STORE* ctx, const int& trust)
{
    if (!X509_STORE_set_trust(ctx, trust)) {
        qCritical() << "Couldn't set trust for X509_STORE. X509_STORE_set_trust() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setDefaultPaths
/// \param ctx - OpenSSL X509_STORE
/// \return
///
bool QSimpleCrypto::QX509Store::setDefaultPaths(X509_STORE* ctx)
{
    if (!X509_STORE_set_default_paths(ctx)) {
        qCritical() << "Couldn't set default paths for X509_STORE. X509_STORE_set_default_paths() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::loadLocations
/// \param ctx - OpenSSL X509_STORE
/// \param filePath
/// \param dirPath
/// \return
///
bool QSimpleCrypto::QX509Store::loadLocations(X509_STORE* ctx, const QByteArray& filePath, const QByteArray& dirPath)
{
    if (!X509_STORE_load_locations(ctx, filePath, dirPath)) {
        qCritical() << "Couldn't load locations for X509_STORE. X509_STORE_load_locations() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::loadLocations
/// \param ctx - OpenSSL X509_STORE
/// \param file
/// \return
///
bool QSimpleCrypto::QX509Store::loadLocations(X509_STORE* ctx, const QFile& file)
{
    QFileInfo info(file);

    if (!X509_STORE_load_locations(ctx, info.fileName().toLocal8Bit(), info.absoluteDir().path().toLocal8Bit())) {
        qCritical() << "Couldn't load locations for X509_STORE. X509_STORE_load_locations() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::loadLocations
/// \param ctx - OpenSSL X509_STORE
/// \param fileInfo
/// \return
///
bool QSimpleCrypto::QX509Store::loadLocations(X509_STORE* ctx, const QFileInfo& fileInfo)
{
    if (!X509_STORE_load_locations(ctx, fileInfo.fileName().toLocal8Bit(), fileInfo.absoluteDir().path().toLocal8Bit())) {
        qCritical() << "Couldn't load locations for X509_STORE. X509_STORE_load_locations() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}
