//
// Created by AJ Poulter on 02/11/2020.
//

#include "SRUP_Syndicated_Data.h"

SRUP_MSG_SYNDICATED_DATA::SRUP_MSG_SYNDICATED_DATA()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_SYNDICATED_DATA;
    m_data = nullptr;
    m_data_ID = nullptr;
    m_data_ID_len = 0;
    m_data_len = 0;
    m_source_ID = nullptr;
}

SRUP_MSG_SYNDICATED_DATA::~SRUP_MSG_SYNDICATED_DATA()
{
    delete m_source_ID;
}

bool SRUP_MSG_SYNDICATED_DATA::Serialize(bool preSign)
{
    // As we're using dynamic memory - and only storing / sending the length of the data we have
    // we need to know how long all of the fields are so that we can unmarshall the data at
    // the other end...

    const uint16_t header_size = 18; // Two-bytes for the main header - plus 8 for the sequence ID ...
                                     // 8 for the sender ID
    const uint8_t field_length_size = 2;

    // We need the number of variable length fields - including the m_sig_len...
    // ... this can't be const as we need to change it depending on whether or not we're in pre-sign.
    // (If we are we need to reduce it by one for the unused m_sig_len)
    // We have the signature, the token, the data_ID & the data...
    uint8_t var_length_field_count = 4;

    const uint8_t len_source = 8; // 8 bytes for the 64-bit source ID.

    uint32_t serial_len;
    uint32_t p=0;

    uint8_t * msb;
    uint8_t * lsb;

    if (m_token == nullptr)
        return false;

    msb=new uint8_t[1];
    lsb=new uint8_t[1];

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

    // ...and check that we have a source ID
    if (m_source_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // If we're calling this as a prelude to signing / verifying then we need to exclude the signature data from the
    // serial data we generate...

    if (preSign)
    {
        serial_len = m_token_len + m_data_ID_len + m_data_len + len_source;
        var_length_field_count--;
    }
    else
        serial_len = m_sig_len + m_token_len + m_data_ID_len + m_data_len + len_source;

    m_serial_length = serial_len + header_size + (field_length_size * var_length_field_count);

    delete[] m_serialized;

    m_serialized = new uint8_t[m_serial_length];
    std::memset(m_serialized, 0, m_serial_length);

    // The first two fields are fixed length (1 byte each).
    std::memcpy(m_serialized, m_version, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_msgtype, 1);
    p+=1;

    // Now we need to add the Sequence ID (uint64_t)
    // See SRUP_Init.cpp for details...
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_sequence_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    // And we need to do the same thing for the Sender ID (uint64_t)
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_sender_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    // All of the other fields need their length to be specified...

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
        {
            delete[] msb;
            delete[] lsb;
            return false;
        }
        else
        {
            if (m_sig_len == 0)
            {
                delete[] msb;
                delete[] lsb;
                return false;
            }
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

    encodeLength(lsb, msb, m_data_ID_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_data_ID, m_data_ID_len);
    p+=m_data_ID_len;

    encodeLength(lsb, msb, m_data_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_data, m_data_len);
    p+=m_data_len;

    // Lastly we need to do add the source ID (uint64_t) - using the same approach as for other uint64_t values…
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_source_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

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

bool SRUP_MSG_SYNDICATED_DATA::DataCheck()
{
    if ((m_data != nullptr) && (m_data_ID != nullptr) && (m_token != nullptr) && (m_sequence_ID != nullptr) && (m_sender_ID != nullptr) && (m_source_ID != nullptr))
        return true;
    else
        return false;
}


const uint64_t *SRUP_MSG_SYNDICATED_DATA::sourceID()
{
    return m_source_ID;
}

bool SRUP_MSG_SYNDICATED_DATA::sourceID(const uint64_t *source)
{
    try
    {
        if (m_source_ID != nullptr)
            delete(m_source_ID);

        m_source_ID = new uint64_t;
        std::memcpy(m_source_ID, source, sizeof(*source));
    }
    catch (...)
    {
        m_source_ID = nullptr;
        return false;
    }
    return true;
}

bool SRUP_MSG_SYNDICATED_DATA::DeSerialize(const uint8_t *serial_data)
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

    // Next we have to unmarshall the sender ID...
    uint8_t snd_bytes[8];
    for (unsigned char & snd_byte : snd_bytes)
    {
        std::memcpy(&snd_byte, (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into the sender ID
    if (m_sender_ID != nullptr)
        delete(m_sender_ID);
    m_sender_ID = new uint64_t;
    std::memcpy(m_sender_ID, snd_bytes, 8);

    // Now we have two-bytes for the size of the token ... and x bytes for the token
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    delete[] m_token;
    m_token = new uint8_t[x+1];
    std::memcpy(m_token, (uint8_t *) serial_data + p, x);
    m_token_len = x;
    p+=x;

    // The next two bytes are the size of the signature...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;

    m_sig_len = x;

    // The next x bytes are the value of the signature.
    delete[] m_signature;
    m_signature = new unsigned char[x];
    std::memcpy(m_signature, serial_data + p, x);

    p+=x;

    // Next the data_ID...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    delete[] m_data_ID;
    m_data_ID = new uint8_t[x+1];
    std::memcpy(m_data_ID, (uint8_t *) serial_data + p, x);
    m_data_ID_len = x;
    p+=x;

    // ...and now the data
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;

    delete[] m_data;
    m_data = new uint8_t[x+1];
    std::memcpy(m_data, (uint8_t *) serial_data + p, x);
    m_data_len = x;
    p+=x;

    // And finally we have to unmarshall the source ID...
    uint8_t src_bytes[8];
    for (unsigned char & src_byte : src_bytes)
    {
        std::memcpy(&src_byte, (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into the source ID
    delete(m_source_ID);
    m_source_ID = new uint64_t;
    std::memcpy(m_source_ID, src_bytes, 8);

    return true;
}