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
    uint8_t *msb;
    uint8_t *lsb;

    msb = new uint8_t[1];
    lsb = new uint8_t[1];

    const unsigned short header_size = 18; // 2 + 8 + 8 - to include session ID & sender ID...
    unsigned short p = 0;

    // Serial length is the header + two-byte token length, plus the length of the token in bytes.
    m_serial_length = header_size + 2 + m_token_len;

    if (m_serialized != nullptr)
        delete (m_serialized);

    // Now check that we have a sequence ID...
    // Technically we don't need one - but we might want use this to check a generic message for a valid sequence ID
    // before we map it onto the correct message type - so we'll include it here.
    if (m_sequence_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // ...by the same logic - we'll also check for the sender ID - as it too, is a part of the "base" message...
    if (m_sender_ID == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

    // ...and lastly for the token.
    if (m_token == nullptr)
    {
        delete[] msb;
        delete[] lsb;
        return false;
    }

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

    // And lastly the token...
    encodeLength(lsb, msb, m_token_len);
    std::memcpy(m_serialized + p, msb, 1);
    p+=1;
    std::memcpy(m_serialized + p, lsb, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_token, m_token_len);

    delete(msb);
    delete(lsb);

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
    uint16_t x;
    uint8_t bytes[2];

    // We need to unmarshall the data to reconstruct the object...
    // We'll only try to extract the "generic" fields (version, type, sequence ID, sender ID, token)

    std::memcpy(m_version, serial_data, 1);
    p+=1;
    std::memcpy(m_msgtype, serial_data + p, 1);
    p+=1;

    // Given that we'll typically deserialize first into the generic message format - we need to try to validate that
    // this is a valid message ... and not some other type of data on the MQTT topic...
    // We'll try checking that the version is okay...

    if (*m_version != SRUP::SRUP_VERSION)
        return false;

    if (not (ValidMessageType (m_msgtype)))
        return false;

    // If we make it to here – there's a good chance the message is a valid one...

    // Now we have to unmarshall the sequence ID...
    uint8_t sid_bytes[8];
    for (int x = 0; x < 8; x++)
    {
        std::memcpy(&sid_bytes[x], (uint8_t *) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sequence_ID
    if (m_sequence_ID != nullptr)
        delete (m_sequence_ID);
    m_sequence_ID = new uint64_t;
    std::memcpy(m_sequence_ID, sid_bytes, 8);

    // We will also unmarshall the sender ID...
    uint8_t snd_bytes[8];
    for (int x = 0; x < 8; x++)
    {
        std::memcpy(&snd_bytes[x], (uint8_t *) serial_data + p, 1);
        ++p;
    }

    // ... then we copy them into m_sender_ID
    if (m_sender_ID != nullptr)
        delete (m_sender_ID);
    m_sender_ID = new uint64_t;
    std::memcpy(m_sender_ID, snd_bytes, 8);

    // Now the token - the last of the "generic" fields...
    std::memcpy(bytes, serial_data + p, 2);
    x = decodeLength(bytes);
    p += 2;
    if (m_token != nullptr)
        delete (m_token);
    m_token = new uint8_t[x];
    std::memcpy(m_token, (uint8_t *) serial_data + p, x);
    m_token_len = x;

    return true;
}

bool SRUP_MSG_GENERIC::DataCheck()
{
    // We can never sign or verify a generic object - so we'll always return false
    return false;
}

bool SRUP_MSG_GENERIC::ValidMessageType (uint8_t *msgtype)
{
    return ((*msgtype == SRUP::SRUP_MESSAGE_TYPE_INITIATE) or
        (*msgtype == SRUP::SRUP_MESSAGE_TYPE_GENERIC) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_RESPONSE) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_ACTIVATE) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_DATA) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_ACTION) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_ID_REQUEST) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_OBSERVE_REQ) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_REQ) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_OBS_JOIN_RESP) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_HM_JOIN_RESP) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_GROUP_DELETE) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_OBS_JOIN_REQ) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_JOIN_REQ) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_TERMINATE_CMD) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_GROUP_ADD) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_HM_JOIN_REQ) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_JOIN_CMD) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_RESIGN_REQUEST) or
        (*msgtype != SRUP::SRUP_MESSAGE_TYPE_GROUP_DESTROY)
    );
}


