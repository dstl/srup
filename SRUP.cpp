//
// Created by AJ Poulter on 27/04/2016.
//

#include "SRUP.h"

SRUP_MSG::SRUP_MSG()
{
    m_version = new char[1];
    m_msgtype = new char[1];

    // We won't actually allocate any space for the other members in the constructor...
    // We'll do that dynamically on assignment.

    m_version[0] = SRUP::SRUP_VERSION;

    m_sig_len = 0;
    m_unsigned_length = 0;

    m_is_serialized = false;

    m_signature = nullptr;
    m_token = nullptr;
    m_serialized = nullptr;
    m_unsigned_message = nullptr;
    m_sequence_ID = nullptr;
}

SRUP_MSG::~SRUP_MSG()
{
    delete[] m_version;
    delete[] m_msgtype;

    if (m_unsigned_message != nullptr)
        delete(m_unsigned_message);

    if (m_signature!= nullptr)
        delete(m_signature);

    if (m_token!= nullptr)
        delete(m_token);

    if (m_serialized != nullptr)
        delete (m_serialized);
    if (m_sequence_ID != nullptr)
        delete (m_sequence_ID);
}

void SRUP_MSG::encodeLength(unsigned char* LSB, unsigned char* MSB, size_t l)
{
    // size_t is unsigned - so we don't need to check for -ve values...
    *LSB=(l % 256);
    *MSB=(l / 256);
}

unsigned short SRUP_MSG::decodeLength(const unsigned char* data)
{
    unsigned short x=0;

    x = data[0] << 8;
    x += data[1];

    return x;
}

char* SRUP_MSG::version()
{
    return m_version;
}

char* SRUP_MSG::msgtype()
{
    return m_msgtype;
}

unsigned char* SRUP_MSG::signature()
{
    return m_signature;
}

bool SRUP_MSG::token(const char* t)
{
    int i;
    try
    {
        if (m_token != nullptr)
            delete(m_token);

        i = std::strlen(t);
        m_token = new char[i+1];
        std::memcpy(m_token, t, i);
        *(m_token + i) = 0;
    }
    catch (...)
    {
        m_token = nullptr;
        return false;
    }

    return true;
}

const char* SRUP_MSG::token()
{
    return m_token;
}

bool SRUP_MSG::Sign(char *keyfile)
{
    if (!DataCheck())
        return false;

    m_is_serialized = false;

    SRUP_Crypto Crypto;
    unsigned char* p_signature;

    // Running Serialize with preSign = true - will set m_serialized to the byte stream to be signed...
    Serialize(true);
    if (Crypto.Sign(m_unsigned_message, m_unsigned_length, keyfile) == nullptr)
        return false;

    p_signature = Crypto.signature();
    m_sig_len = Crypto.sigLen();

    if (m_signature != nullptr)
        delete(m_signature);
    m_signature = new unsigned char[m_sig_len];

    memcpy(m_signature, p_signature, m_sig_len);

    return true;
}

bool SRUP_MSG::Verify(char *keyfile)
{
    if (!DataCheck())
        return false;

    SRUP_Crypto Crypto;
    Crypto.setSignature(m_signature, m_sig_len);
    Serialize(true);
    return Crypto.Verify(m_unsigned_message, m_unsigned_length, keyfile);
}

const uint64_t *SRUP_MSG::sequenceID()
{
    return m_sequence_ID;
}

bool SRUP_MSG::sequenceID(const uint64_t *sid)
{
    try
    {
        if (m_sequence_ID != nullptr)
            delete(m_sequence_ID);

        m_sequence_ID = new uint64_t;
        std::memcpy(m_sequence_ID, sid, sizeof(unsigned long long int));
    }
    catch (...)
    {
        m_sequence_ID = nullptr;
        return false;
    }
    return true;
}

uint8_t SRUP_MSG::getByteVal(uint64_t ull, int p)
{
    // Given that we have a 64-bit value – we only have 8 bits to play with...
    if ((p<0) || (p>7))
        return 0;

    uint8_t byte_val;
    byte_val = ull >> 8*p;
    return byte_val;
}
