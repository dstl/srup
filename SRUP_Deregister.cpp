//
// Created by AJ Poulter on 04/05/2018.
//

#include "SRUP_Deregister.h"

SRUP_MSG_DEREGISTER_REQ::SRUP_MSG_DEREGISTER_REQ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_REQ;
}
