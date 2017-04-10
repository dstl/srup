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
    const unsigned short header_size = 2;
    unsigned short p=0;

    m_serial_length = header_size;

    if (m_serialized != nullptr)
        delete (m_serialized);

    m_serialized = new unsigned char[m_serial_length];
    std::memset(m_serialized, 0, m_serial_length);

    // The first two fields are fixed length (1 byte each).
    std::memcpy(m_serialized, m_version, 1);
    p+=1;
    std::memcpy(m_serialized + p, m_msgtype, 1);
    p+=1;

    return true;
}

size_t SRUP_MSG_GENERIC::SerializedLength()
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

    return true;
}

bool SRUP_MSG_GENERIC::DataCheck()
{
    // We can never sign or verify a generic object - so we'll always fail
    return false;
}



