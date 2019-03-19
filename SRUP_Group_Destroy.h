//
// Created by AJ Poulter on 12/06/2018.
//

#ifndef SRUP_LIB_SRUP_GROUP_DESTROY_H
#define SRUP_LIB_SRUP_GROUP_DESTROY_H

#include "SRUP.h"

// This is the group destroy message; unlike the group base-class it only provides the base-message fields,
// and the group name. There's no device ID in the destroy message.

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_GROUP_DESTROY = 0x14;
}


class SRUP_MSG_GROUP_DESTROY : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_GROUP_DESTROY();
    ~SRUP_MSG_GROUP_DESTROY();

    bool group_ID(const uint8_t*, const uint16_t);
    const uint8_t* group_ID();

    uint16_t group_ID_length();

    uint8_t* Serialized();
    bool DeSerialize(const uint8_t*);
    uint32_t SerializedLength();

protected:
    bool Serialize(bool optional = false);
    bool DataCheck();
    uint8_t* m_group_id;
    uint16_t m_group_id_len;
};

#endif //SRUP_LIB_SRUP_GROUP_DESTROY_H
