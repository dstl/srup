//
// Created by AJ Poulter on 04/05/2018.
//

#include "SRUP_Resign.h"

SRUP_MSG_RESIGN_REQ::SRUP_MSG_RESIGN_REQ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_RESIGN_REQUEST;
}
