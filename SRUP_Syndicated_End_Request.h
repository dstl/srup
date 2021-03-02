//
// Created by AJ Poulter on 10/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_END_REQUEST_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_END_REQUEST_H

#include "SRUP_Simple.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_SYNDICATION_END = 0x2E;
}

// The only thing that we need to do is define the constructor...

class SRUP_MSG_SYNDICATED_END_REQ : public SRUP_MSG_SIMPLE
{
    using SRUP_MSG_SIMPLE::SRUP_MSG_SIMPLE;

public:
    SRUP_MSG_SYNDICATED_END_REQ();
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_END_REQUEST_H
