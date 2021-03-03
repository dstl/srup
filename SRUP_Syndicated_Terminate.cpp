//
// Created by AJ Poulter on 10/11/2020.
//

#include "SRUP_Syndicated_Terminate.h"

SRUP_MSG_SYNDICATED_TERMINATE::SRUP_MSG_SYNDICATED_TERMINATE ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_SYNDICATION_TERMINATE;
}
