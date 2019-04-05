//
// Created by AJ Poulter on 14/05/2018.
//

#ifndef SRUP_LIB_SRUP_OBSERVED_JOIN_H
#define SRUP_LIB_SRUP_OBSERVED_JOIN_H

#include "SRUP_Simple.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_OBS_JOIN_REQ = 0x0D;
}

// This is the Observed Join Request – which doesn't have the encrypted field used for the Human Join Response, the
// Observed Join Response, or the Observation Request...
// So we need to do two things here – define the constructor & add the observer ID (plus methods)...

class SRUP_MSG_OBSERVED_JOIN_REQ : public SRUP_MSG_SIMPLE
{
    using SRUP_MSG_SIMPLE::SRUP_MSG_SIMPLE;

public:
    SRUP_MSG_OBSERVED_JOIN_REQ();
    ~SRUP_MSG_OBSERVED_JOIN_REQ();

    bool DeSerialize(const uint8_t *);

    const uint64_t* observer_ID();
    bool observer_ID(const uint64_t*);

protected:
    uint64_t* m_observer_id;

    bool Serialize(bool optional = false);
    bool DataCheck();
};

#endif //SRUP_LIB_SRUP_OBSERVED_JOIN_H
