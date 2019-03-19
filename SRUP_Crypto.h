//
// Created by AJ Poulter on 03/08/2016.
//

#ifndef SRUP_SRUP_CRYPTO_H
#define SRUP_SRUP_CRYPTO_H

#include <cstdio>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

class SRUP_Crypto
{
public:
    SRUP_Crypto();
    ~SRUP_Crypto();

    unsigned char* Sign(unsigned char *, size_t, char *);
    bool Verify(unsigned char *, size_t, char *);

    bool Encrypt(uint8_t *, int, char*);
    uint8_t* Decrypt(char*);

    unsigned char* SignF(unsigned char *, size_t, char *);
    bool VerifyF(unsigned char *, size_t, char *);

    bool EncryptF(uint8_t *, int, char*);
    uint8_t* DecryptF(char*);


    uint8_t* crypt();
    void crypt(uint8_t *, uint16_t);

    uint16_t cryptLen();

    uint8_t* signature();
    void signature(uint8_t*, uint16_t);
    uint16_t sigLen();

private:
    unsigned char* m_signature;
    unsigned int m_sig_length;

    uint16_t m_crypt_length;
    uint8_t* m_crypt;

    uint8_t* m_plain_text;
    uint16_t m_plain_text_length;

    RSA* getPubKeyF(char*);
    RSA* getPubKey(char*);
    RSA* getPrivateKeyF(char*);
    RSA* getPrivateKey(char*);

    unsigned char* _Sign(unsigned char *, size_t, RSA*);
    bool _Verify(unsigned char *, size_t, RSA*);

    bool _Encrypt(uint8_t *, int, RSA*);
    uint8_t* _Decrypt(RSA*);
};


#endif //SRUP_SRUP_CRYPTO_H
