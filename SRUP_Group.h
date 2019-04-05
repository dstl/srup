//
// Created by AJ Poulter on 14/05/2018.
//

#ifndef SRUP_LIB_SRUP_GROUP_BASE_H
#define SRUP_LIB_SRUP_GROUP_BASE_H

#include "SRUP.h"

// This is the base-class for the "group" message types (excluding the group destroy message).
// This class provides the base-message fields, the device ID, plus a group name.

class SRUP_MSG_GROUP_BASE : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    ~SRUP_MSG_GROUP_BASE();

    bool group_ID(const uint8_t*, const uint16_t);
    const uint8_t* group_ID();

    const uint64_t* device_ID();
    bool device_ID(const uint64_t*);

    uint16_t group_ID_length();

    uint8_t* Serialized();
    bool DeSerialize(const uint8_t*);
    uint32_t SerializedLength();

protected:
    // We'd ideally like the constructor to be virtual - but as we can't do that in C++ we'll make the constructor
    // a protected method – that way you the compiler will prevent instantiation ...
    SRUP_MSG_GROUP_BASE();

    bool Serialize(bool optional = false);
    bool DataCheck();
    uint64_t* m_device_id;
    uint8_t* m_group_id;
    uint16_t m_group_id_len;
};

#endif //SRUP_LIB_SRUP_GROUP_BASE_H
