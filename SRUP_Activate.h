//
// Created by AJ Poulter on 28/06/2016.
//

#ifndef SRUP_LIB_SRUP_ACTIVATE_H
#define SRUP_LIB_SRUP_ACTIVATE_H

#include "SRUP.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_ACTIVATE = 0x03;
}

// Lastly we have the SRUP_MSG_ACTIVATE
// There's nothing to add to the base-class - though we do need to implement the virtual functions to do with Serialization

class SRUP_MSG_ACTIVATE : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_ACTIVATE();
    ~SRUP_MSG_ACTIVATE();

    unsigned char* Serialized();
    bool DeSerialize(const uint8_t *);
    uint32_t SerializedLength();

protected:
    bool Serialize(bool optional = false);
    bool DataCheck();

};

#endif //SRUP_LIB_SRUP_ACTIVATE_H
