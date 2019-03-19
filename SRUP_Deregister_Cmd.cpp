//
// Created by AJ Poulter on 04/05/2018.
//

#include "SRUP_Deregister_Cmd.h"

SRUP_MSG_DEREGISTER_CMD::SRUP_MSG_DEREGISTER_CMD()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_CMD;
}
