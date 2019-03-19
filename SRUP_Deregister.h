//
// Created by AJ Poulter on 04/05/2018.
//

#ifndef SRUP_LIB_SRUP_DEREGISTER_H
#define SRUP_LIB_SRUP_DEREGISTER_H

#include "SRUP_Simple.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_DEREGISTER_REQ = 0x12;
}

// The only thing that we need to do is define the constructor...

class SRUP_MSG_DEREGISTER_REQ : public SRUP_MSG_SIMPLE
{
    using SRUP_MSG_SIMPLE::SRUP_MSG_SIMPLE;

public:
    SRUP_MSG_DEREGISTER_REQ();
};

#endif //SRUP_LIB_SRUP_DEREGISTER_H
