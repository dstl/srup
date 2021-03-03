//
// Created by AJ Poulter on 11/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATION_REQUEST_H
#define SRUP_LIBRARY_SRUP_SYNDICATION_REQUEST_H

#include "SRUP_Observed_Base.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_SYNDICATION_REQUEST = 0x29;
}

// The only thing that we need to do is define the constructor...

class SRUP_MSG_SYNDICATION_REQUEST : public SRUP_MSG_OBS_BASE
{
    using SRUP_MSG_OBS_BASE::SRUP_MSG_OBS_BASE;

public:
    SRUP_MSG_SYNDICATION_REQUEST();
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATION_REQUEST_H
