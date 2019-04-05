//
// Created by AJ Poulter on 25/05/2018.
//

#include "SRUP_Observation_Req.h"

SRUP_MSG_OBSERVE_REQ::SRUP_MSG_OBSERVE_REQ()
{
    m_msgtype[0] = SRUP::SRUP_MESSAGE_TYPE_OBSERVE_REQ;
}