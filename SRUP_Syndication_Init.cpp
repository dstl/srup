//
// Created by AJ Poulter on 11/11/2020.
//

#include "SRUP_Syndication_Init.h"

SRUP_MSG_SYNDICATION_INIT::SRUP_MSG_SYNDICATION_INIT ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_SYNDICATION_INIT;
    m_url = nullptr;
    m_url_len = 0;
}

SRUP_MSG_SYNDICATION_INIT::~SRUP_MSG_SYNDICATION_INIT ()
{
    delete[] m_url;
}

bool SRUP_MSG_SYNDICATION_INIT::url (const char *url, uint16_t url_len)
{
    m_is_serialized = false;

    try
    {
        delete[] m_url;

        m_url_len = url_len;
        m_url = new char[m_url_len];
        std::strncpy(m_url, url, m_url_len);
    }
    catch (...)
    {
        m_url = nullptr;
        return false;
    }

    return true;
}

char *SRUP_MSG_SYNDICATION_INIT::url ()
{
    return m_url;
}

uint16_t SRUP_MSG_SYNDICATION_INIT::url_length () const
{
    return m_url_len;
}

uint8_t *SRUP_MSG_SYNDICATION_INIT::Serialized ()
{
    if (Serialize(false))
        return m_serialized;
    else
        return nullptr;
}

bool SRUP_MSG_SYNDICATION_INIT::DataCheck ()
{
    {
        if((m_url != nullptr) && (m_token != nullptr) && (m_sender_ID !=nullptr) && (m_sequence_ID != nullptr))
            return true;
        else
            return false;
    }
}

uint32_t SRUP_MSG_SYNDICATION_INIT::SerializedLength ()
{
    if (!m_is_serialized)
        Serialize(false);

    return m_serial_length;
}

bool SRUP_MSG_SYNDICATION_INIT::DeSerialize (const uint8_t *serial_data)
{
    uint16_t x;
    uint32_t p=0;
    uint8_t bytes[2];

    // We need to unmarshall the data to reconstruct the object...
    // We can start with the two bytes for the header.
    // One for the version - and one for the message type.

    std::memcpy(m_version, (uint8_t*) serial_data, 1);
    p+=1;
    std::memcpy(m_msgtype, (uint8_t*) serial_data + p, 1);
    p+=1;

    // Now we have to unmarshall the sequence ID...
    // Reconstructing it from the 8x uint8_t's we have in the bytestream...
    // First we get the 8-bytes...
    uint8_t sid_bytes[8];
    for (unsigned char & sid_byte : sid_bytes)
    {
        std::memcpy(&sid_byte, (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sequence_ID
    if (m_sequence_ID != nullptr)
        delete(m_sequence_ID);
    m_sequence_ID = new uint64_t;
    std::memcpy(m_sequence_ID, sid_bytes, 8);

    // Again we have to do the same trick to unmarshall the sender ID...
    // Reconstructing it from the 8x uint8_t's we have in the bytestream...
    uint8_t snd_bytes[8];
    for (unsigned char & snd_byte : snd_bytes)
    {
        std::memcpy(&snd_byte, (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sender_ID
    if (m_sender_ID != nullptr)
        delete(m_sender_ID);
    m_sender_ID = new uint64_t;
    std::memcpy(m_sender_ID, snd_bytes, 8);

    // Now the token - the last of the "generic" fields...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    delete[] m_token;
    m_token = new uint8_t[x];
    std::memcpy(m_token, (uint8_t *) serial_data + p, x);
    m_token_len = x;
    p+=x;

    // Most of the rest of the fields are simpler...

    // The next two bytes are the size of the signature...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;

    m_sig_len = x;

    // The next x bytes are the value of the signature.
    delete[] m_signature;
    m_signature = new uint8_t[x];
    std::memcpy(m_signature, serial_data + p, x);

    p+=x;

    // Now finally on to the remaining (simple) fields...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    delete[] m_url;
    m_url = new char[x+1];
    std::memcpy(m_url, (uint8_t *) serial_data + p, x);
    *(m_url + x) = 0;
    m_url_len = x;
    p+=x;

    // Lastly we have the encrypted data.
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;

    auto* encrypted_data = new uint8_t[x];

    std::memcpy(encrypted_data, (uint8_t *) serial_data + p, x);
    m_crypto->crypt(encrypted_data, x);

    delete[] encrypted_data;

    return true;
}

bool SRUP_MSG_SYNDICATION_INIT::Serialize (bool preSign)
{
    // As we're using dynamic memory - and only storing / sending the length of the data we have
    // we need to know how long all of the fields are so that we can unmarshall the data at
    // the other end...

    const uint16_t fixed_size = 18; // Two-bytes for the main header - plus 8 for the sequence ID & 8 for sender_ID...
    const uint16_t field_length_size = 2; // We use two-bytes each to store the length of the variable length fields

    // We need the number of variable length fields - including the m_sig_len...
    // ... this can't be const as we need to change it depending on whether or not we're in pre-sign.
    // (If we are we need to reduce it by one for the unused m_sig_len)
    // We have four variable length fields: token, encrypted_data, url & signature.
    uint8_t var_length_field_count = 4;

    uint32_t serial_len;
    uint32_t p=0;

    uint8_t * msb;
    uint8_t * lsb;

    msb=new uint8_t[1];
    lsb=new uint8_t[1];

    // Check to see if these strings are assigned before we try to do anything with them...
    if(m_token == nullptr || m_url == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // Now check that we have a sequence ID...
    if (m_sequence_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // ...and check that we have a sender ID
    if (m_sender_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // If we're calling this as a prelude to signing / verifying then we need to exclude the signature data from the
    // serial data we generate...

    if (preSign)
    {
        // Don't include the sig_len in serial_len – and reduce the var_length_field_count by one to exclude
        // the signature...
        serial_len = m_token_len + m_url_len + m_crypto->cryptLen();
        var_length_field_count--;
    }
    else
        serial_len = m_sig_len + m_token_len + m_url_len + m_crypto->cryptLen();

    m_serial_length = serial_len + fixed_size + (field_length_size * var_length_field_count);

    delete[] m_serialized;

    m_serialized = new uint8_t[m_serial_length];
    std::memset(m_serialized, 0, m_serial_length);

    // The first two fields are fixed length (1 byte each).
    std::memcpy(m_serialized, m_version, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_msgtype, 1);
    p+=1;

    // Now we need to add the Sequence ID (uint64_t)
    // But we need to ensure that we get the correct byte-order ... or at least a consistent byte-order!
    // Given the use of encodeLength & sending the msb first (big-endian / network byte-order) – we need to do the same
    // Simply doing std::memcpy(m_serialized + p, m_sequence_ID, 8) – won't give us the right answer on (e.g. x86 arch)
    // so we need to get the value one byte at a time...
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_sequence_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    // We now do the exact same thing for the sender ID - also uint64_t...
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_sender_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    // All of the other fields need their length to be specified...

    // TOKEN...
    encodeLength(lsb, msb, m_token_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_token, m_token_len);
    p+=m_token_len;

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
                // SIGNATURE...
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

    // URL...
    encodeLength(lsb, msb, m_url_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_url, m_url_len);
    p+=m_url_len;

    // Lastly we need to add the encrypted data...
    int crypt_len = m_crypto->cryptLen();
    encodeLength(lsb, msb, crypt_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;

    uint8_t* encrypted_data=m_crypto->crypt();
    std::memcpy(m_serialized + p, encrypted_data, crypt_len);
    //p+=crypt_len; - unused since this is the final operation

    delete[] msb;
    delete[] lsb;

    // If we're in preSign we don't have a real value for m_serialized - so copy the data to m_unsigned_message
    // and discard (and reset) m_serialized & m_serial_length...
    if (preSign)
    {
        delete[] m_unsigned_message;
        m_unsigned_message = new unsigned char[m_serial_length];

        std::memcpy(m_unsigned_message, m_serialized, m_serial_length);
        m_unsigned_length = m_serial_length;

        m_serial_length = 0;
        delete[] m_serialized;
        m_serialized= nullptr;
    }

    m_is_serialized = true;
    return true;
}
