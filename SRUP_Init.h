//
// Created by AJ Poulter on 28/06/2016.
//

#ifndef SRUP_LIB_SRUP_INIT_H
#define SRUP_LIB_SRUP_INIT_H

#include "SRUP.h"

namespace SRUP
{
    static const unsigned char SRUP_MESSAGE_TYPE_INITIATE = 0x01;
}

// The SRUP_MSG_INIT message type adds the device UUID (target), as well as the URL of the data file & its digest.

class SRUP_MSG_INIT : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_INIT();
    ~SRUP_MSG_INIT();

    unsigned char* Serialized();
    bool DeSerialize(const unsigned char*);
    size_t SerializedLength();

    bool target(const char*);
    char* target();
    bool url(const char*);
    char* url();
    bool digest(const char*);
    char* digest();

protected:
    char* m_target;
    char* m_url;
    char* m_digest;

    bool Serialize(bool optional = false);
    bool DataCheck();
};

#endif //SRUP_LIB_SRUP_INIT_H
