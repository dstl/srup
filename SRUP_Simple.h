//
// Created by AJ Poulter on 11/05/2018.
//

#ifndef SRUP_LIB_SRUP_SIMPLE_H
#define SRUP_LIB_SRUP_SIMPLE_H

#include "SRUP.h"

// This is the base-class for all of the "simple" message types - that only consist of the base-message fields.
// There's nothing to add to the base-class - but we do need to implement the virtual functions to do with Serialization

class SRUP_MSG_SIMPLE : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    ~SRUP_MSG_SIMPLE();

    unsigned char* Serialized();
    bool DeSerialize(const uint8_t *);
    uint32_t SerializedLength();

protected:
    // We'd ideally like the constructor to be virtual - but as we can't do that in C++ we'll make the constructor
    // a protected method – that way you the compiler will prevent instantiation ...
    SRUP_MSG_SIMPLE();
    bool Serialize(bool optional = false);
    bool DataCheck();

};

#endif //SRUP_LIB_SRUP_SIMPLE_H
