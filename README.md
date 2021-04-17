### QSimpleCrypto
Small C++ cryptographic library based on **Qt** and **OpenSSL**.

This library also working with **Android**.

#

### Dependencies
This library requires no special dependencies except of [**Qt**](https://www.qt.io/) with the [**OpenSSL (version 1.1.1 or later)**](https://www.openssl.org/).

#

#### AES Block Sizes
  [AES-128, AES-192, AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

#

#### AES Ciphers
- Electronic codebook ([ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)))
- Cipher block chaining ([CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)))
- Cipher feedback ([CFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)))
- Output Feedback ([OFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)))
- Counter Mode ([CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)))
- Galois/Counter Mode ([GCM](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Galois/Counter_(GCM)))
- Counter with Cipher Block Chaining-Message Authentication Code ([CCM](https://en.wikipedia.org/wiki/CCM_mode))

#

#### Cryptosystems
- RSA ([Rivest–Shamir–Adleman](https://en.wikipedia.org/wiki/RSA_(cryptosystem)))

#

#### Certificates
- [X509](https://en.wikipedia.org/wiki/X.509)

#

### Build
Before building lib, you have to add **OpenSSL** lib to root folder or change path in `.pro` file.

```
cd <projectDirecoty>
qmake QSimpleCrypto.pro 
make
```

#

### How to use
To get started, you need to add [**OpenSSL**](https://www.openssl.org/source/) library to your project.

You can download [**OpenSSL**](https://www.openssl.org/source/) on:
* **Qt Maintenance Tool** (downloaded files will be in **Qt/Tools/** folder)
* [**OpenSSL site**](https://www.openssl.org/source/).

After building library and linking **OpenSSL**, you need to link **QSimpleCrypto** to your project.

#

**Example:**
```cpp
#include <QDebug>
#include <QByteArray>

#include "QAEAD.h"

int main() {
    QByteArray key = "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT";
    QByteArray iv = "AABBCCEEFFGGHHKKLLMMNNOOPPRRSSTT";
    QByteArray aad = "AABBCCDDEEFF";
    QByteArray tag = "AABBCCDDEEFF";

    QSimpleCrypto::QAEAD aead;
    QByteArray encrypted = aead.encryptAesGcm("Hello World", key, iv, &tag, aad);
    QByteArray decrypted = aead.decryptAesGcm(bytes, key, iv, &tag, aad);    
}
```


*Note: encryption and decryption functions returns value in hex dimension. So, if you want to display encrypted or decrypted value you should [convert](https://doc.qt.io/qt-5/qbytearray.html#toBase64) or [deconvert](https://doc.qt.io/qt-5/qbytearray.html#fromBase64) received value.*

More information you can find on [wiki](https://github.com/bru74lw1z4rd/QSimpleCrypto/wiki).
