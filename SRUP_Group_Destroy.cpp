//
// Created by AJ Poulter on 12/06/2018.
//

#include "SRUP_Group_Destroy.h"

SRUP_MSG_GROUP_DESTROY::SRUP_MSG_GROUP_DESTROY()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_GROUP_DESTROY;

    m_group_id = nullptr;
    m_group_id_len = 0;
}

SRUP_MSG_GROUP_DESTROY::~SRUP_MSG_GROUP_DESTROY()
{
    if (m_group_id != nullptr)
        delete(m_group_id);
}

bool SRUP_MSG_GROUP_DESTROY::Serialize(bool preSign)
{
    // As we're using dynamic memory - and only storing / sending the length of the data we have
    // we need to know how long all of the fields are so that we can unmarshall the data at
    // the other end...

    const uint16_t header_size = 18; // Two-bytes for the main header - plus 8 for the seq. ID, plus 8 for the sender ID 
    const uint8_t field_length_size = 2;

    // We need the number of variable length fields - including the m_sig_len...
    // ... this can't be const as we need to change it depending on whether or not we're in pre-sign.
    // (If we are we need to reduce it by one for the unused m_sig_len)
    // Here it will be 3 - signature, token, and group_id...
    uint8_t var_length_field_count = 3;

    uint32_t serial_len;
    uint32_t p=0;

    uint8_t * msb;
    uint8_t * lsb;

    if (m_token == nullptr)
        return false;

    // Now check that we have a sequence ID...
    if (m_sequence_ID == nullptr)
        return false;

    // ...and check that we have a sender ID ...
    if (m_sender_ID == nullptr)
        return false;

    // ...and check that we have a group ID
    if (m_group_id == nullptr)
        return false;

    msb=new uint8_t[1];
    lsb=new uint8_t[1];

    // If we're calling this as a prelude to signing / verifying then we need to exclude the signature data from the
    // serial data we generate...

    if (preSign)
    {
        serial_len = m_token_len + m_group_id_len;
        var_length_field_count--;
    }
    else
        serial_len = m_sig_len + m_token_len + m_group_id_len;

    m_serial_length = serial_len + header_size + (field_length_size * var_length_field_count);

    if (m_serialized != nullptr)
        delete (m_serialized);

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

    // For the other fields need their length to be specified...

    // The token...
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

    // Lastly we need to add the group ID...
    encodeLength(lsb, msb, m_group_id_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_group_id, m_group_id_len);

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

uint32_t SRUP_MSG_GROUP_DESTROY::SerializedLength()
{
    if (!m_is_serialized)
        Serialize();

    return m_serial_length;
}

uint8_t* SRUP_MSG_GROUP_DESTROY::Serialized()
{
    if (Serialize())
        return m_serialized;
    else
        return nullptr;
}

bool SRUP_MSG_GROUP_DESTROY::DeSerialize(const unsigned char* serial_data)
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
    for (int i=0;i<8;i++)
    {
        std::memcpy(&sid_bytes[i], (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sequence_ID
    if (m_sequence_ID != nullptr)
        delete(m_sequence_ID);
    m_sequence_ID = new uint64_t;
    std::memcpy(m_sequence_ID, sid_bytes, 8);

    // Next we have to unmarshall the sender ID...
    uint8_t snd_bytes[8];
    for (int i=0;i<8;i++)
    {
        std::memcpy(&snd_bytes[i], (uint8_t*) serial_data + p, 1);
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
    if(m_token != nullptr)
        delete(m_token);
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
    if(m_signature != nullptr)
        delete(m_signature);
    m_signature = new uint8_t[x];
    std::memcpy(m_signature, serial_data + p, x);

    p+=x;
    
    // Lastly we have the group ID.
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p+=2;
    if(m_group_id != nullptr)
        delete(m_group_id);
    m_group_id = new uint8_t[x+1];
    std::memcpy(m_group_id, (uint8_t *) serial_data + p, x);
    m_group_id_len = x;

    return true;
}

bool SRUP_MSG_GROUP_DESTROY::group_ID(const uint8_t* group_id, const uint16_t len)
{
    m_is_serialized = false;

    if (m_group_id != nullptr)
        delete (m_group_id);

    m_group_id = new uint8_t[len];
    std::memcpy(m_group_id, group_id, len);
    m_group_id_len = len;
    return true;
}

const uint8_t* SRUP_MSG_GROUP_DESTROY::group_ID()
{
    return m_group_id;
}

bool SRUP_MSG_GROUP_DESTROY::DataCheck()
{
    if ((m_group_id != nullptr) && (m_token != nullptr) && (m_sequence_ID != nullptr) && (m_sender_ID != nullptr))
        return true;
    else
        return false;
}

uint16_t SRUP_MSG_GROUP_DESTROY::group_ID_length()
{
    return m_group_id_len;
}
