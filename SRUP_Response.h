//
// Created by AJ Poulter on 28/06/2016.
//

#ifndef SRUP_LIB_SRUP_RESPONSE_H
#define SRUP_LIB_SRUP_RESPONSE_H

#include "SRUP.h"

namespace SRUP
{
    static const unsigned char SRUP_MESSAGE_TYPE_RESPONSE = 0x02;
    namespace UPDATE
    {
        static const unsigned char SRUP_UPDATE_SUCCESS = 0x00;
        static const unsigned char SRUP_UPDATE_FAIL_SERVER = 0xFD;
        static const unsigned char SRUP_UPDATE_FAIL_FILE = 0xFE;
        static const unsigned char SRUP_UPDATE_FAIL_DIGEST = 0xFF;
    }
}

// For the SRUP_MSG_RESPONSE class we need to add the status field (i.e. the return value that indicates the outcome).
class SRUP_MSG_RESPONSE : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_RESPONSE();
    ~SRUP_MSG_RESPONSE();

    unsigned char* Serialized();
    bool DeSerialize(const unsigned char*);
    size_t SerializedLength();

    bool status(const unsigned char);
    unsigned char * status();

protected:
    bool Serialize(bool optional = false);
    bool DataCheck();
    unsigned char* m_status;


};

#endif //SRUP_LIB_SRUP_RESPONSE_H
