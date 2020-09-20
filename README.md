### QSimpleCrypto
Small cryptographic C++ library based on Qt and OpenSSL

#

### Dependencies
This library requires no special dependencies except of [**Qt**](https://www.qt.io/) with the [**OpenSSL (version 1.1.1 or later)**](https://www.openssl.org/).

#

#### Cipher
  [AES-128, AES-192, AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

#

#### Cipher mode of operation
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

```
cd <projectDirecoty>
qmake QSimpleCrypto.pro 
make
```

#

### How to use

* To use this library, you need to add **OpenSSL** to your project.
 

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

More information you can find on [wiki](https://github.com/bru74lw1z4rd/QSimpleCrypto/wiki/Where-to-start).
