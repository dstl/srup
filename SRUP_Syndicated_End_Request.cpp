//
// Created by AJ Poulter on 10/11/2020.
//

#include "SRUP_Syndicated_End_Request.h"

SRUP_MSG_SYNDICATED_END_REQ::SRUP_MSG_SYNDICATED_END_REQ ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_SYNDICATION_END;
}
