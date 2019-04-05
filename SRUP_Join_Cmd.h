//
// Created by AJ Poulter on 04/05/2018.
//

#ifndef SRUP_LIB_SRUP_JOIN_CMD_H
#define SRUP_LIB_SRUP_JOIN_CMD_H


#include "SRUP_Simple.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_JOIN_CMD = 0x0A;
}

// This one is unlike the other classes inheriting from SRUP_MSG_SIMPLE – as we need to add the target device ID for the
// device that's being added (this message type is sent using a generic channel).
// We do still also need to define the constructor too...

class SRUP_MSG_JOIN_CMD : public SRUP_MSG_SIMPLE
{
    using SRUP_MSG_SIMPLE::SRUP_MSG_SIMPLE;

public:
    SRUP_MSG_JOIN_CMD();
    ~SRUP_MSG_JOIN_CMD();

    bool DeSerialize(const uint8_t *);

    const uint64_t* device_ID();
    bool device_ID(const uint64_t*);

protected:
    bool Serialize(bool optional = false);
    bool DataCheck();

    uint64_t* m_device_id;
};

#endif //SRUP_LIB_SRUP_JOIN_CMD_H
