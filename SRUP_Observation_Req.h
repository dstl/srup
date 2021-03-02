//
// Created by AJ Poulter on 25/05/2018.
//

#ifndef SRUP_LIB_SRUP_OBSERVE_REQ_H
#define SRUP_LIB_SRUP_OBSERVE_REQ_H

#include "SRUP_Observed_Base.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_OBSERVE_REQ = 0x0F;
}

// The only thing that we need to do is define the constructor...

class SRUP_MSG_OBSERVE_REQ : public SRUP_MSG_OBS_BASE
{
    using SRUP_MSG_OBS_BASE::SRUP_MSG_OBS_BASE;

public:
    SRUP_MSG_OBSERVE_REQ();
    ~SRUP_MSG_OBSERVE_REQ() override;

    bool DeSerialize(const uint8_t *) override;

    unsigned char* Serialized() override;
    uint32_t SerializedLength() override;

    const uint64_t* joining_device_ID();
    bool joining_device_ID(const uint64_t*);

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;

    uint64_t* m_joining_device_id;
};

#endif //SRUP_LIB_SRUP_OBSERVE_REQ_H
