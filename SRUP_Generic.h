//
// Created by AJ Poulter on 08/07/2016.
//

#ifndef SRUP_SRUP_GENERIC_H
#define SRUP_SRUP_GENERIC_H


#include "SRUP.h"
#include "SRUP_Init.h"
#include "SRUP_Data.h"
#include "SRUP_Activate.h"
#include "SRUP_Response.h"
#include "SRUP_Action.h"
#include "SRUP_ID_REQ.h"
#include "SRUP_Observation_Req.h"
#include "SRUP_Deregister.h"
#include "SRUP_Observed_Join_Resp.h"
#include "SRUP_Human_Join_Resp.h"
#include "SRUP_Observed_Join.h"
#include "SRUP_Join.h"
#include "SRUP_Terminate.h"
#include "SRUP_Human_Join.h"
#include "SRUP_Join_Cmd.h"
#include "SRUP_Resign.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_GENERIC = 0x00;
}

// This is a proxy for the base-class - we only implement the version & type...
// We'll use this to read an unknown message-type before we re-read it with the correct class...

// There's nothing to add to the base-class - though we do need to implement the virtual functions to do with Serialization
class SRUP_MSG_GENERIC : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_GENERIC();
    ~SRUP_MSG_GENERIC() override = default;

    unsigned char* Serialized() override;
    bool DeSerialize(const unsigned char*) override;
    uint32_t SerializedLength() override;

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    static bool ValidMessageType(const uint8_t*);

};

#endif //SRUP_SRUP_GENERIC_H
