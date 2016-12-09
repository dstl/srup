//
// Created by AJ Poulter on 08/07/2016.
//

#ifndef SRUP_SRUP_GENERIC_H
#define SRUP_SRUP_GENERIC_H


#include "SRUP.h"

namespace SRUP
{
    static const unsigned char SRUP_MESSAGE_TYPE_GENERIC = 0x00;
}

// This is a proxy for the base-class - we only implement the version & type...
// We'll use this to read an unknown message-type before we re-read it with the correct class...

// There's nothing to add to the base-class - though we do need to implement the virtual functions to do with Serialization
class SRUP_MSG_GENERIC : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_GENERIC();
    ~SRUP_MSG_GENERIC();

    unsigned char* Serialized();
    bool DeSerialize(const unsigned char*);
    size_t SerializedLength();

protected:
    bool Serialize(bool optional = false);
    bool DataCheck();

};

#endif //SRUP_SRUP_GENERIC_H
