//
// Created by AJ Poulter on 14/05/2018.
//

#ifndef SRUP_LIB_SRUP_GROUP_DELETE_H
#define SRUP_LIB_SRUP_GROUP_DELETE_H

#include "SRUP_Group.h"

// The only thing that we need to do is define the constructor & the message type value..

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_GROUP_DELETE = 0x08;
}

class SRUP_MSG_GROUP_DELETE : public  SRUP_MSG_GROUP_BASE
{
    using SRUP_MSG_GROUP_BASE::SRUP_MSG_GROUP_BASE;

public:
    SRUP_MSG_GROUP_DELETE();
};

#endif //SRUP_LIB_SRUP_GROUP_DELETE_H
