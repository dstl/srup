//
// Created by AJ Poulter on 11/05/2018.
//

#ifndef SRUP_LIB_SRUP_GROUP_ADD_H
#define SRUP_LIB_SRUP_GROUP_ADD_H

#include "SRUP_Group.h"


// The only thing that we need to do is define the constructor & the message type value..

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_GROUP_ADD = 0x07;
}

class SRUP_MSG_GROUP_ADD : public  SRUP_MSG_GROUP_BASE
{
    using SRUP_MSG_GROUP_BASE::SRUP_MSG_GROUP_BASE;

public:
    SRUP_MSG_GROUP_ADD();
};

#endif //SRUP_LIB_SRUP_GROUP_ADD_H
