//
// Created by AJ Poulter on 10/05/2017.
//

#ifndef SRUP_TESTS_SRUP_ACTION_H
#define SRUP_TESTS_SRUP_ACTION_H

#include "SRUP.h"

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_ACTION = 0x04;
}

// Next we add SRUP_MSG_ACTION
// We need to add the uint8_t for the action ID to the base-class...
// and we also must implement the virtual functions to do with Serialization

class SRUP_MSG_ACTION : public  SRUP_MSG
{
    //using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_ACTION();
    ~SRUP_MSG_ACTION() override;

    bool action_ID(const uint8_t*);
    const uint8_t* action_ID();

    uint8_t* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint8_t* m_action;
};

#endif //SRUP_TESTS_SRUP_ACTION_H
