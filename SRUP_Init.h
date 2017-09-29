//
// Created by AJ Poulter on 28/06/2016.
//

#ifndef SRUP_LIB_SRUP_INIT_H
#define SRUP_LIB_SRUP_INIT_H

#include "SRUP.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_INITIATE = 0x01;
}

// The SRUP_MSG_INIT message type adds the device UUID (target), as well as the URL of the data file & its digest.

class SRUP_MSG_INIT : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_INIT();
    ~SRUP_MSG_INIT();

    uint8_t* Serialized();
    bool DeSerialize(const uint8_t*);
    uint32_t SerializedLength();

    bool target(const uint8_t*, uint16_t);
    uint8_t* target();
    uint16_t target_length();
    bool url(const char*);
    char* url();
    bool digest(const uint8_t*, uint16_t);
    uint8_t* digest();

protected:
    uint8_t* m_target;
    char* m_url;
    uint8_t* m_digest;

    uint16_t m_url_len;
    uint16_t m_target_len;
    uint16_t m_digest_len;

    bool Serialize(bool optional = false);
    bool DataCheck();
};

#endif //SRUP_LIB_SRUP_INIT_H
