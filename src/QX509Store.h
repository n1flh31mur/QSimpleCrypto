#ifndef QX509STORE_H
#define QX509STORE_H

#include <QDebug>

#include <openssl/err.h>
#include <openssl/x509_vfy.h>

namespace QSimpleCrypto
{
    class QX509Store
    {
    public:
        QX509Store();

        bool addCertificateToStore(X509_STORE* store, X509* x509);
        bool setDepth(X509_STORE* store, const int& depth);
    };
}

#endif // QX509STORE_H
