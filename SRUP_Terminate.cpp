//
// Created by AJ Poulter on 04/05/2018.
//

#include "SRUP_Terminate.h"

SRUP_MSG_TERMINATE_CMD::SRUP_MSG_TERMINATE_CMD()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_TERMINATE_CMD;
}
