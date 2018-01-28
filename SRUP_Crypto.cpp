//
// Created by AJ Poulter on 03/08/2016.
//

#include "SRUP_Crypto.h"


SRUP_Crypto::SRUP_Crypto()
{
    m_signature = nullptr;
    m_sig_length=0;
}

SRUP_Crypto::~SRUP_Crypto()
{
    if (m_signature != nullptr)
        delete(m_signature);
}

unsigned char *SRUP_Crypto::Sign(unsigned char *data, size_t datasize, char *keyfile)
{
    RSA* key;
    int sigsize;

    FILE* fp = fopen(keyfile, "rb");
    if (fp == NULL)
        return nullptr;
    else
    {
        key = RSA_new();
        key = PEM_read_RSAPrivateKey(fp, &key, NULL, NULL);
        sigsize = RSA_size(key);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data, datasize, hash);
        m_signature = new unsigned char [sigsize];

        RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, m_signature, &m_sig_length, key);
        RSA_free(key);

        return m_signature;
    }
}

bool SRUP_Crypto::Verify(unsigned char *data, size_t datasize, char *keyfile)
{
    RSA *key;
    bool rval;
    BN_CTX* c;

    // When verifying the signature - we use the public key...
    FILE *fp = fopen(keyfile, "rb");
    if (fp == NULL)
        return false;
    else
    {
        key = RSA_new();
        key = PEM_read_RSA_PUBKEY(fp, &key, NULL, NULL);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data, datasize, hash);

        c=BN_CTX_new();
        RSA_blinding_on(key, c);

        // Now perform the verify...
        rval = (bool) RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, m_signature, m_sig_length, key);

        // ...and turn off the blinding
        RSA_blinding_off(key);
        BN_CTX_free(c);

        RSA_free(key);
        fclose(fp);
        return rval;
    }
}

unsigned char *SRUP_Crypto::signature()
{
    return m_signature;
}

unsigned int SRUP_Crypto::sigLen()
{
    return m_sig_length;
}

void SRUP_Crypto::setSignature(unsigned char *signature, unsigned int sig_len)
{
    if (m_signature != nullptr)
        delete(m_signature);
    m_signature = new unsigned char [sig_len];
    std::memcpy(m_signature, signature, sig_len);
    m_sig_length = sig_len;
}
