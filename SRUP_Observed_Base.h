//
// Created by AJ Poulter on 24/05/2018.
//

#ifndef SRUP_LIB_OBSERVED_BASE_H
#define SRUP_LIB_OBSERVED_BASE_H

#include "SRUP.h"
#include "SRUP_Crypto.h"

// This is the base-class for all of the "observed" join messages - which consist of the base-message fields, plus the
// encrypted value used to confirm identity.
// So in addition to the base-class; we add the encrypted data; and the associated methods.
// We also need to implement all the virtual functions to do with Serialization.


class SRUP_MSG_OBS_BASE : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    ~SRUP_MSG_OBS_BASE();

    const uint8_t* encrypted_data(bool, char*);
    bool encrypted_data(uint8_t*, uint16_t, bool, char*);

    unsigned char* Serialized();
    bool DeSerialize(const uint8_t *);
    uint32_t SerializedLength();

protected:
    // We'd ideally like the constructor to be virtual - but as we can't do that in C++ we'll make the constructor
    // a protected method – that way you the compiler will prevent instantiation ...
    SRUP_MSG_OBS_BASE();
    bool Serialize(bool optional = false);
    bool DataCheck();

    SRUP_Crypto* m_crypto;

};
#endif //SRUP_LIB_OBSERVED_BASE_H
