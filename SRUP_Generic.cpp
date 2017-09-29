//
// Created by AJ Poulter on 08/07/2016.
//

#include "SRUP_Generic.h"


SRUP_MSG_GENERIC::SRUP_MSG_GENERIC()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_GENERIC;
}

SRUP_MSG_GENERIC::~SRUP_MSG_GENERIC()
{

}

bool SRUP_MSG_GENERIC::Serialize(bool preSign)
{
    const unsigned short header_size = 18; // 2 + 8 + 8 - to include session ID & sender ID...
    unsigned short p=0;

    m_serial_length = header_size;

    if (m_serialized != nullptr)
        delete (m_serialized);

    // Now check that we have a sequence ID...
    // Technically we don't need one - but we might want to check a generic message for a valid sequence ID before
    // we map it onto the correct message type - so we'll include it here.
    if (m_sequence_ID == nullptr)
        return false;

    // ...by the same logic - we'll also check for the sender ID - as it too, is a part of the "base" message...
    if (m_sender_ID == nullptr)
        return false;

    m_serialized = new unsigned char[m_serial_length];
    std::memset(m_serialized, 0, m_serial_length);

    // The first two fields are fixed length (1 byte each).
    std::memcpy(m_serialized, m_version, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_msgtype, 1);
    p+=1;

    // Now we need to add the Sequence ID
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_sequence_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    // And the sender ID
    for (int x=0;x<8;x++)
    {
        uint8_t byte;
        byte = getByteVal(*m_sender_ID, x);
        std::memcpy(m_serialized + p, &byte, 1);
        p+=1;
    }

    return true;
}

uint32_t SRUP_MSG_GENERIC::SerializedLength()
{
    Serialize(false);
    return m_serial_length;
}

unsigned char *SRUP_MSG_GENERIC::Serialized()
{
    if (Serialize())
        return m_serialized;
    else
        return nullptr;
}

bool SRUP_MSG_GENERIC::DeSerialize(const unsigned char* serial_data)
{
    unsigned int p=0;

    // We need to unmarshall the data to reconstruct the object...
    // We only need the first two however: the two bytes for the header.
    // One for the version - and one for the message type.

    std::memcpy(m_version, serial_data, 1);
    p+=1;
    std::memcpy(m_msgtype, serial_data + p, 1);
    p+=1;

    // Now we have to unmarshall the sequence ID...
    uint8_t sid_bytes[8];
    for (int x=0;x<8;x++)
    {
        std::memcpy(&sid_bytes[x], (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sequence_ID
    if (m_sequence_ID != nullptr)
        delete(m_sequence_ID);
    m_sequence_ID = new uint64_t;
    std::memcpy(m_sequence_ID, sid_bytes, 8);

    // We will also unmarshall the sender ID...
    uint8_t snd_bytes[8];
    for (int x=0;x<8;x++)
    {
        std::memcpy(&snd_bytes[x], (uint8_t*) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sender_ID
    if (m_sender_ID != nullptr)
        delete(m_sender_ID);
    m_sender_ID = new uint64_t;
    std::memcpy(m_sender_ID, snd_bytes, 8);

    return true;
}

bool SRUP_MSG_GENERIC::DataCheck()
{
    // We can never sign or verify a generic object - so we'll always return false
    return false;
}



