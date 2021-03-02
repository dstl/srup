//
// Created by AJ Poulter on 10/11/2020.
//

#include "SRUP_Syndicated_Device_List.h"

SRUP_MSG_SYNDICATED_DEV_LIST::SRUP_MSG_SYNDICATED_DEV_LIST ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_SYNDICATED_DEV_LIST;
    m_device_sequence = nullptr;
    m_device_ID = nullptr;
}

SRUP_MSG_SYNDICATED_DEV_LIST::~SRUP_MSG_SYNDICATED_DEV_LIST ()
{
    delete m_device_sequence;
    delete m_device_ID;
}

bool SRUP_MSG_SYNDICATED_DEV_LIST::device_sequence (const uint32_t * sequence)
{
    m_is_serialized = false;
    delete m_device_sequence;
    m_device_sequence = new uint32_t;
    *m_device_sequence = *sequence;

    return true;
}

uint32_t *SRUP_MSG_SYNDICATED_DEV_LIST::device_sequence ()
{
    return m_device_sequence;
}

bool SRUP_MSG_SYNDICATED_DEV_LIST::deviceID (const uint64_t *dev_id)
{
    m_is_serialized = false;
    delete m_device_ID;
    m_device_ID = new uint64_t;
    *m_device_ID = *dev_id;

    return true;
}
uint64_t *SRUP_MSG_SYNDICATED_DEV_LIST::deviceID ()
{
    return m_device_ID;
}

uint8_t *SRUP_MSG_SYNDICATED_DEV_LIST::Serialized ()
{
    if (Serialize(false))
        return m_serialized;
    else
        return nullptr;
}

bool SRUP_MSG_SYNDICATED_DEV_LIST::DeSerialize (const uint8_t *serial_data)
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
    if(m_signature != nullptr)
        delete[] m_signature;
    m_signature = new uint8_t[x];
    std::memcpy(m_signature, serial_data + p, x);

    p+=x;

    // Next we have four bytes for the device sequence.
    uint8_t ds_bytes[4];
    for (unsigned char & ds_byte : ds_bytes)
    {
        std::memcpy(&ds_byte, (uint8_t*) serial_data + p, 1);
        ++p;
    }

    delete(m_device_sequence);
    m_device_sequence = new uint32_t;
    std::memcpy(m_device_sequence, ds_bytes, 4);

    // And finally the device ID.
    uint8_t did_bytes[8];
    for (unsigned char & did_byte : did_bytes)
    {
        std::memcpy(&did_byte, (uint8_t*) serial_data + p, 1);
        ++p;
    }

    delete(m_device_ID);
    m_device_ID = new uint64_t;
    std::memcpy(m_device_ID, did_bytes, 8);

    return true;
}

uint32_t SRUP_MSG_SYNDICATED_DEV_LIST::SerializedLength ()
{
    if (!m_is_serialized)
        Serialize(false);

    return m_serial_length;
}


bool SRUP_MSG_SYNDICATED_DEV_LIST::Serialize (bool preSign)
{
    // As we're using dynamic memory - and only storing / sending the length of the data we have
    // we need to know how long all of the fields are so that we can unmarshall the data at
    // the other end...

    const uint16_t header_size = 18; // Two-bytes for the main header - plus 8 for the sequence ID ...
    // 8 for the sender ID

    const uint8_t field_length_size = 2;

    const uint8_t len_seq = 4;  // 4 bytes for the 32-bit device sequence.
    const uint8_t len_did = 8;  // 4 bytes for the 64-bit device ID.

    // We need the number of variable length fields - including the m_sig_len...
    // ... this can't be const as we need to change it depending on whether or not we're in pre-sign.
    // (If we are we need to reduce it by one for the unused m_sig_len
    uint8_t var_length_field_count = 2;

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

    // ...and check that we have a sender ID ...
    if (m_sender_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // ...and check that we have a device sequence...
    if (m_device_sequence == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // ...and check that we have a device ID
    if (m_device_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }


    // If we're calling this as a prelude to signing / verifying then we need to exclude the signature data from the
    // serial data we generate...

    if (preSign)
    {
        serial_len = m_token_len + len_seq + len_did;
        var_length_field_count--;
    }
    else
        serial_len = m_sig_len + m_token_len + len_seq + len_did;

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

    // Next we need to add the device sequence (uint32_t)
    for (int x=0;x<4;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_device_sequence, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    // And finally the device ID (8-bytes)
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_device_ID, x);
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

bool SRUP_MSG_SYNDICATED_DEV_LIST::DataCheck ()
{
    if ((m_device_ID != nullptr) && (m_token != nullptr) && (m_sequence_ID != nullptr) && (m_sender_ID != nullptr) &&
                                                                                         (m_device_sequence != nullptr))
        return true;
    else
        return false;
}