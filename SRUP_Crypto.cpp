//
// Created by AJ Poulter on 03/08/2016.
//

#include <stdexcept>
#include "SRUP_Crypto.h"


SRUP_Crypto::SRUP_Crypto()
{
    m_signature = nullptr;
    m_crypt = nullptr;
    m_plain_text = nullptr;

    m_sig_length=0;
    m_crypt_length=0;
    m_plain_text_length=0;
}

SRUP_Crypto::~SRUP_Crypto()
{
    delete[] m_signature;
    delete[] m_crypt;
    delete[] m_plain_text;
}

RSA* SRUP_Crypto::getPubKeyF(char *keyfile)
{
    RSA *key;
    FILE *fp = fopen(keyfile, "rb");
    if (!fp)
        return nullptr;
    else
    {
        key = RSA_new();
        key = PEM_read_RSA_PUBKEY(fp, &key, nullptr, nullptr);
        fclose(fp);
        return key;
    }
}

RSA* SRUP_Crypto::getPubKey(char *key_string)
{
    RSA *key;

    BIO* bo = BIO_new(BIO_s_mem());

    BIO_write(bo, key_string, strlen(key_string));

    key = RSA_new();
    key = PEM_read_bio_RSA_PUBKEY(bo, &key, nullptr, nullptr);
    if(!key)
        return nullptr;
    BIO_free(bo);
    return key;
}

RSA* SRUP_Crypto::getPrivateKeyF(char *keyfile)
{
    RSA *key;

    FILE *fp = fopen(keyfile, "rb");
    if (!fp)
        return nullptr;
    else
    {
        key = RSA_new();
        key = PEM_read_RSAPrivateKey(fp, &key, nullptr, nullptr);
        fclose(fp);
        return key;
    }
}

RSA* SRUP_Crypto::getPrivateKey(char *key_string)
{
    RSA* key;

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, key_string, strlen(key_string));

    key = RSA_new();
    key = PEM_read_bio_RSAPrivateKey(bo, &key, nullptr, nullptr);
    if(!key)
        return nullptr;

    BIO_free(bo);
    return key;
}

unsigned char* SRUP_Crypto::_sign(unsigned char *data, size_t datasize, RSA *key)
{
    if (key == nullptr)
        return nullptr;
    
    int sigsize;
    sigsize = RSA_size(key);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, datasize, hash);
    m_signature = new unsigned char [sigsize];

    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, m_signature, &m_sig_length, key);

    RSA_free(key);
    return m_signature;
}

bool SRUP_Crypto::_verify(unsigned char *data, size_t datasize, RSA *key)
{
    if (key == nullptr)
        return false;
    
    bool rval;
    BN_CTX* c;

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
    return rval;
}

bool SRUP_Crypto::_encrypt(uint8_t *data, int input_datasize, RSA *rsa_key)
{
    int evp_key_len;
    int iv_len;

    uint8_t body[4096];
    int body_len;

    uint8_t final[4096];
    int final_len;

    uint8_t* evp_key = nullptr;
    uint8_t iv[EVP_MAX_IV_LENGTH];

    EVP_PKEY *pkey;
    EVP_CIPHER_CTX* ctx;

    pkey = EVP_PKEY_new();

    // Next we need to assign the "envelope key" & init...
    if (!EVP_PKEY_assign_RSA(pkey, rsa_key))
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);
    evp_key = new uint8_t[EVP_PKEY_size(pkey)];
    if (!EVP_SealInit(ctx, EVP_aes_256_cbc(), &evp_key, &evp_key_len, iv, &pkey, 1))
    {
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        delete[] evp_key;
        return false;
    }

    // Having initialized (generated the initialization vector (iv) and the symmetric key we next do the encryption
    if (!EVP_SealUpdate(ctx, body, &body_len, data, input_datasize))
    {
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        delete[] evp_key;
        return false;
    }

    // We finish with EVP_SealFinal to take care of any padding
    if (!EVP_SealFinal(ctx, final, &final_len))
    {
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        delete[] evp_key;
        return false;
    }

    // Lastly we need to write the encrypted (symmetric) key length, the encrypted (symmetric) key; and the
    // initialization vector to the return value...along with the encrypted version of the data.

    // We start by calculating the size of the return value.
    iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());

    // The crypt length is equal to:
    // key length (sizeof(int)=4) + key length + IV length + data size (sizeof(int)=4)) +
    // input data size (sizeof(int)=4)) + data (body + final (including padding))
    m_crypt_length = sizeof(int) + evp_key_len + iv_len + sizeof(int) + sizeof(int) + body_len + final_len;

    delete[] m_crypt;
    m_crypt = new uint8_t[m_crypt_length];

    int x=0;

    // Now we're ready to write the encrypted data to m_crypt...
    // The order here is:
    //
    // encrypted (symmetric) key length
    std::memcpy(m_crypt, &evp_key_len, sizeof(int));
    x+=sizeof(int);

    // encrypted (symmetric) key
    std::memcpy(m_crypt+x, evp_key, (size_t) evp_key_len);
    x+=evp_key_len;

    // initialization vector (this has a fixed length – so we don't need to store it)
    std::memcpy(m_crypt+x, iv, (size_t) iv_len);
    x+=iv_len;

    // encrypted data size
    int encrypted_data_size = body_len + final_len;
    std::memcpy(m_crypt+x, &encrypted_data_size, sizeof(int));
    x+=sizeof(int);

    // Now the unencrypted data size (so we can reconstruct the data on the other side)
    std::memcpy(m_crypt+x, &input_datasize, sizeof(int));
    x+=sizeof(int);

    // And finally the encrypted data – first the main block of encrypted data...
    std::memcpy(m_crypt+x, body, (size_t) body_len);
    x+=body_len;

    // ...then the final data block (including any padding)
    // NOTE: this rather assumes that we'll never get data larger than 128-bytes. We'll need to change this if we're
    // expecting that not to be the case.
    std::memcpy(m_crypt+x, final, (size_t) final_len);

    EVP_PKEY_free(pkey);
    EVP_CIPHER_CTX_free(ctx);
    delete[] evp_key;

    return true;
}

uint8_t* SRUP_Crypto::_decrypt(RSA *rsa_key)
{
    EVP_CIPHER_CTX* ctx;
    EVP_PKEY *pkey;
    uint8_t* evp_key;

    int evp_key_len;
    int iv_len;
    uint8_t body[4096];
    int body_len;
    uint8_t final[4096];
    int final_len;
    uint8_t iv[EVP_MAX_IV_LENGTH];

    int read_size;
    int data_size;

    pkey = EVP_PKEY_new();

    if (!EVP_PKEY_assign_RSA(pkey, rsa_key))
    {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    ctx=EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);
    int x=0;

    // We now start reading data from m_crypt - in the same order as we wrote it...

    // Key length
    std::memcpy(&evp_key_len, m_crypt, sizeof(int));
    x+=sizeof(int);
    if (evp_key_len > EVP_PKEY_size(pkey))
    {
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    evp_key = new uint8_t[evp_key_len];

    // Key value
    std::memcpy(evp_key, m_crypt+x, (size_t) evp_key_len);
    x+= evp_key_len;

    // IV (a fixed size...)
    iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    std::memcpy(&iv, m_crypt+x, (size_t) iv_len);
    x+=iv_len;

    // Encrypted data size
    std::memcpy(&read_size, m_crypt+x, sizeof(int));
    x+=sizeof(int);

    // Actual data size (excluding padding)
    std::memcpy(&data_size, m_crypt+x, sizeof(int));
    x+=sizeof(int);

    // Now the encrypted data
    // Initialize...
    if (!EVP_OpenInit(ctx, EVP_aes_256_cbc(), evp_key, evp_key_len, iv, pkey))
    {
        delete[] evp_key;
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    // ...read the first block...
    if (!EVP_OpenUpdate(ctx, body, &body_len, m_crypt+x, read_size))
    {
        delete[] evp_key;
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    // ... and then read the final block (including padding)
    // See previous note about expected data sizes...
    if (!EVP_OpenFinal(ctx, final, &final_len))
    {
        delete[] evp_key;
        EVP_PKEY_free(pkey);
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    m_plain_text_length = (uint16_t) body_len + (uint16_t) final_len;
    m_plain_text = new uint8_t[m_plain_text_length];
    std::memcpy(m_plain_text, body, (size_t) body_len);
    std::memcpy(m_plain_text + body_len, final, (size_t) data_size - body_len);

    EVP_PKEY_free(pkey);
    EVP_CIPHER_CTX_free(ctx);
    delete[] evp_key;

    return m_plain_text;
}

uint8_t* SRUP_Crypto::SignF(unsigned char *data, size_t datasize, char *keyfile)
{
    RSA* key;
    key = getPrivateKeyF(keyfile);

    if (key!= nullptr)
        return _sign(data, datasize, key);
    else
        return nullptr;
}

uint8_t* SRUP_Crypto::Sign(unsigned char *data, size_t datasize, char *key_string)
{
    RSA* key;
    key = getPrivateKey(key_string);
    return _sign(data, datasize, key);
}

bool SRUP_Crypto::VerifyF(unsigned char *data, size_t datasize, char *keyfile)
{
    RSA* key;
    key = getPubKeyF(keyfile);
    if (key != nullptr)
        return _verify(data, datasize, key);
    else
        return false;
}

bool SRUP_Crypto::Verify(unsigned char *data, size_t datasize, char *key_string)
{
    RSA *key;
    key = getPubKey(key_string);
    return _verify(data, datasize, key);
}

bool SRUP_Crypto::EncryptF(uint8_t *data, int input_datasize, char *keyfile)
{
    RSA* key;
    key = getPubKeyF(keyfile);
    if (key != nullptr)
        return _encrypt(data, input_datasize, key);
    else
        return false;
}

bool SRUP_Crypto::Encrypt(uint8_t *data, int input_datasize, char *key_string)
{
    RSA* key;
    key = getPubKey(key_string);
    return _encrypt(data, input_datasize, key);
}

uint8_t* SRUP_Crypto::DecryptF(char *keyfile)
{
    RSA* key;
    key = getPrivateKeyF(keyfile);
    if (key != nullptr)
        return _decrypt(key);
    else
        return nullptr;
}

uint8_t* SRUP_Crypto::Decrypt(char *key_string)
{
    RSA* key;
    key = getPrivateKey(key_string);
    return _decrypt(key);
}


uint16_t SRUP_Crypto::sigLen() const
{
    return (uint16_t) m_sig_length;
}

uint8_t* SRUP_Crypto::signature()
{
    return m_signature;
}

void SRUP_Crypto::signature(uint8_t *signature, uint16_t sig_len)
{
    delete[] m_signature;
    m_signature = new unsigned char [sig_len];
    std::memcpy(m_signature, signature, sig_len);
    m_sig_length = sig_len;
}

void SRUP_Crypto::crypt(uint8_t *data, uint16_t data_len)
{
    delete[] m_crypt;
    m_crypt = new unsigned char [data_len];
    std::memcpy(m_crypt, data, data_len);
    m_crypt_length = data_len;
}

uint8_t* SRUP_Crypto::crypt()
{
    return m_crypt;
}

uint16_t SRUP_Crypto::cryptLen() const
{
    return m_crypt_length;
}


