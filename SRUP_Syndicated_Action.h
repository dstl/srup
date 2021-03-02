//
// Created by AJ Poulter on 05/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_ACTION_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_ACTION_H

#include "SRUP_Action.h"

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_SYNDICATED_ACTION = 0x24;
}

// Next we add SRUP_MSG_SYNDICATED_ACTION

class SRUP_MSG_SYNDICATED_ACTION : public  SRUP_MSG_ACTION
{
    //using SRUP_MSG_ACTION::SRUP_MSG_ACTION;

public:
    SRUP_MSG_SYNDICATED_ACTION();
    ~SRUP_MSG_SYNDICATED_ACTION() override;

    bool DeSerialize(const uint8_t*) override;

    const uint64_t* targetID();
    bool targetID(const uint64_t*);

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint64_t* m_target_ID;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_ACTION_H
