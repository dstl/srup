//
// Created by AJ Poulter on 10/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_ID_REQ_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_ID_REQ_H

#include "SRUP_ID_REQ.h"

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_SYNDICATED_ID_REQUEST = 0x26;
}


class SRUP_MSG_SYNDICATED_ID_REQ : public  SRUP_MSG_ID_REQ
{
    //using SRUP_MSG_ID_REQ::SRUP_MSG_ID_REQ;

public:
    SRUP_MSG_SYNDICATED_ID_REQ();
    ~SRUP_MSG_SYNDICATED_ID_REQ() override;

    bool DeSerialize(const uint8_t*) override;

    const uint64_t* targetID();
    bool targetID(const uint64_t*);

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint64_t* m_target_ID;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_ID_REQ_H
