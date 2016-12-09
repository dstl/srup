//
// Created by AJ Poulter on 28/06/2016.
//

#include "SRUP_Init.h"

SRUP_MSG_INIT::SRUP_MSG_INIT()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_INITIATE;

    m_target = nullptr;
    m_url = nullptr;
    m_digest = nullptr;
}

SRUP_MSG_INIT::~SRUP_MSG_INIT()
{
    if (m_target != nullptr)
        delete (m_target);
    if (m_url != nullptr)
        delete (m_url);
    if (m_digest != nullptr)
        delete (m_digest);
}

bool SRUP_MSG_INIT::Serialize(bool preSign)
{
    // As we're using dynamic memory - and only storing / sending the length of the data we have
    // we need to know how long all of the fields are so that we can unmarshall the data at
    // the other end...

    const int header_size = 2; // Two bytes for the header...
    const int field_length_size = 2;

    // We need the number of variable length fields - including the m_sig_len...
    // ... this can't be const as we need to change it depending on whether or not we're in pre-sign.
    // (If we are we need to reduce it by one for the unused m_sig_len
    int var_length_field_count = 5;

    size_t serial_len;
    int p=0;

    size_t len_target;
    size_t len_token;
    size_t len_url;
    size_t len_digest;

    unsigned int len_sig;

    unsigned char* msb;
    unsigned char* lsb;

    msb=new unsigned char[1];
    lsb=new unsigned char[1];

    // TODO: Consider type-safe assignment to protect against sizes of elements larger than sizeof(short)?
    // Can that ever happen?

    // Check to see if these strings are assigned before we try to call strlen on them...
    if(m_target == nullptr || m_token == nullptr || m_url == nullptr || m_digest == nullptr)
        return false;

    len_target = std::strlen(m_target);
    len_token = std::strlen(m_token);
    len_url = std::strlen(m_url);
    len_digest = std::strlen(m_digest);

    // If we're calling this as a prelude to signing / verifying then we need to exclude the signature data from the
    // serial data we generate...

    if (preSign)
    {
        len_sig = 0;
        var_length_field_count--;
    }
    else
        len_sig = m_sig_len;

    serial_len = len_sig + len_target + len_token + len_url + len_digest;

    m_serial_length = serial_len + header_size + (field_length_size * var_length_field_count);

    if (m_serialized != nullptr)
        delete (m_serialized);

    m_serialized = new unsigned char[m_serial_length];
    std::memset(m_serialized, 0, m_serial_length);

    // The first two fields are fixed length (1 byte each).
    std::memcpy(m_serialized, m_version, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_msgtype, 1);
    p+=1;

    // All of the other fields need their length to be specified...

    // If we're executing Serialize as a part of generating the signature - we can't marshall the signature
    // as we haven't calculated it yet. So only do the signature if we're not in preSign

    if (!preSign)
    {
        if (m_signature == nullptr)
            return false;
        else
        {
            if (m_sig_len == 0)
                return false;
            else
            {
                encodeLength(lsb, msb, m_sig_len);
                std::memcpy(m_serialized + p, msb, 1);
                p += 1;
                std::memcpy(m_serialized + p, lsb, 1);
                p += 1;
                std::memcpy(m_serialized + p, m_signature, m_sig_len);
                p += m_sig_len;
            }
        }
    }

    encodeLength(lsb, msb, len_target);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_target, len_target);
    p+=len_target;

    encodeLength(lsb, msb, len_token);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_token, len_token);
    p+=len_token;

    encodeLength(lsb, msb, len_url);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_url, len_url);
    p+=len_url;

    encodeLength(lsb, msb, len_digest);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_digest, len_digest);

    delete(msb);
    delete(lsb);

    // If we're in preSign we don't have a real value for m_serialized - so copy the data to m_unsigned_message
    // and discard (and reset) m_serialized & m_serial_length...
    if (preSign)
    {
        if (m_unsigned_message != nullptr)
            delete(m_unsigned_message);
        m_unsigned_message = new unsigned char[m_serial_length];

        std::memcpy(m_unsigned_message, m_serialized, m_serial_length);
        m_unsigned_length = m_serial_length;

        m_serial_length = 0;
        delete (m_serialized);
        m_serialized= nullptr;
    }

    m_is_serialized = true;
    return true;
}

size_t SRUP_MSG_INIT::SerializedLength()
{
    if (!m_is_serialized)
        Serialize();

    return m_serial_length;
}

unsigned char* SRUP_MSG_INIT::Serialized()
{
    if (Serialize())
        return m_serialized;
    else
        return nullptr;
}

bool SRUP_MSG_INIT::DeSerialize(const unsigned char* serial_data)
{
    unsigned short x;
    unsigned int p=0;
    unsigned char bytes[2];

    // We need to unmarshall the data to reconstruct the object...
    // We can start with the two bytes for the header.
    // One for the version - and one for the message type.

    std::memcpy(m_version, (char*) serial_data, 1);
    p+=1;
    std::memcpy(m_msgtype, (char*) serial_data + p, 1);
    p+=1;

    // The next two bytes are the size of the signature...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;

    m_sig_len = x;

    // The next x bytes are the value of the signature.
    if(m_signature != nullptr)
        delete(m_signature);
    m_signature = new unsigned char[x];
    std::memcpy(m_signature, serial_data + p, x);

    p+=x;

    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);

    p+=2;
    if(m_target != nullptr)
        delete(m_target);
    m_target = new char[x+1];
    std::memcpy(m_target, (char*) serial_data + p, x);
    *(m_target + x) = 0;
    p+=x;

    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    if(m_token != nullptr)
        delete(m_token);
    m_token = new char[x+1];
    std::memcpy(m_token, (char*) serial_data + p, x);
    *(m_token + x) = 0;
    p+=x;

    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    if(m_url != nullptr)
        delete(m_url);
    m_url = new char[x+1];
    std::memcpy(m_url, (char*) serial_data + p, x);
    *(m_url + x) = 0;
    p+=x;

    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    if(m_digest != nullptr)
        delete(m_digest);
    m_digest = new char[x+1];
    std::memcpy(m_digest, (char*) serial_data + p, x);
    *(m_digest + x) = 0;

    return true;
}

bool SRUP_MSG_INIT::target(const char* t)
{
    m_is_serialized = false;

    int i;
    try
    {
        if (m_target != nullptr)
            delete(m_target);

        i = std::strlen(t);
        m_target = new char[i+1];
        std::memcpy(m_target, t, i);
        *(m_target + i) = 0;
    }
    catch (...)
    {
        m_target = nullptr;
        return false;
    }

    return true;
}


char* SRUP_MSG_INIT::target()
{
    return m_target;
}

bool SRUP_MSG_INIT::url(const char* u)
{
    m_is_serialized = false;

    int i;
    try
    {
        if (m_url != nullptr)
            delete(m_url);

        i = std::strlen(u);
        m_url = new char[i+1];
        std::memcpy(m_url, u, i);
        *(m_url + i) = 0;
    }
    catch (...)
    {
        m_url = nullptr;
        return false;
    }

    return true;
}

char* SRUP_MSG_INIT::url()
{
    return m_url;
}

bool SRUP_MSG_INIT::digest(const char* d)
{
    m_is_serialized = false;

    int i;
    try
    {
        if (m_digest != nullptr)
            delete(m_digest);

        i = std::strlen(d);
        m_digest = new char[i+1];
        std::memcpy(m_digest, d, i);
        *(m_digest + i) = 0;

    }
    catch (...)
    {
        m_digest = nullptr;
        return false;
    }

    return true;
}

char* SRUP_MSG_INIT::digest()
{
    return m_digest;
}

bool SRUP_MSG_INIT::DataCheck()
{
    if((m_digest != nullptr) && (m_target != nullptr) && (m_url != nullptr) && (m_token != nullptr))
        return true;
    else
        return false;
}
