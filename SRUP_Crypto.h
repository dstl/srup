//
// Created by AJ Poulter on 03/08/2016.
//

#ifndef SRUP_SRUP_CRYPTO_H
#define SRUP_SRUP_CRYPTO_H

#include <cstring>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class SRUP_Crypto
{
public:
    SRUP_Crypto();
    ~SRUP_Crypto();
    unsigned char* Sign(unsigned char*, size_t, char*);
    bool Verify(unsigned char*, size_t, char*);
    unsigned char* signature();
    void setSignature(unsigned char*, unsigned int);
    unsigned int sigLen();

private:
    unsigned char* m_signature;
    unsigned int m_sig_length;
};


#endif //SRUP_SRUP_CRYPTO_H
