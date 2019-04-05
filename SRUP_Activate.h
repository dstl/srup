//
// Created by AJ Poulter on 28/06/2016.
//

#ifndef SRUP_LIB_SRUP_ACTIVATE_H
#define SRUP_LIB_SRUP_ACTIVATE_H

#include "SRUP_Simple.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_ACTIVATE = 0x03;
}

// The only thing that we need to do is define the constructor...

class SRUP_MSG_ACTIVATE : public SRUP_MSG_SIMPLE
{
    using SRUP_MSG_SIMPLE::SRUP_MSG_SIMPLE;

public:
    SRUP_MSG_ACTIVATE();
};

#endif //SRUP_LIB_SRUP_ACTIVATE_H
