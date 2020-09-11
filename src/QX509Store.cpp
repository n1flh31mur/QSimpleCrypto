#include "QX509Store.h"

QSimpleCrypto::QX509Store::QX509Store()
{
}

///
/// \brief QSimpleCrypto::QX509::addCertificateToStore
/// \param store - OpenSSL X509_STORE
/// \param x509 - OpenSSL X509
/// \return
///
bool QSimpleCrypto::QX509Store::addCertificateToStore(X509_STORE* store, X509* x509)
{
    if (!X509_STORE_add_cert(store, x509)) {
        qCritical() << "Couldn't add certificate to X509_STORE. X509_STORE_add_cert() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setCertificateDepth
/// \param store - OpenSSL X509_STORE
/// \param depth - Sets the maximum verification depth to depth. Example: 0
/// \return
///
bool QSimpleCrypto::QX509Store::setDepth(X509_STORE* store, const int& depth)
{
    if (!X509_STORE_set_depth(store, depth)) {
        qCritical() << "Couldn't set depth for X509_STORE. X509_STORE_set_depth() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}

///
/// \brief QSimpleCrypto::QX509Store::setFlag
/// \param store - OpenSSL X509_STORE
/// \param flag - The verification flags consists of zero or more of the following flags ored together. Example: X509_V_FLAG_CRL_CHECK
/// \return
///
bool QSimpleCrypto::QX509Store::setFlag(X509_STORE* store, const unsigned long& flag)
{
    if (!X509_STORE_set_flags(store, flag)) {
        qCritical() << "Couldn't set flag for X509_STORE. X509_STORE_set_flags() error: " << ERR_error_string(ERR_get_error(), nullptr);
        return false;
    }

    return true;
}
