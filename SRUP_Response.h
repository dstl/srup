//
// Created by AJ Poulter on 28/06/2016.
//

#ifndef SRUP_LIB_SRUP_RESPONSE_H
#define SRUP_LIB_SRUP_RESPONSE_H

#include "SRUP.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_RESPONSE = 0x02;
    namespace UPDATE
    {
        static const uint8_t SRUP_UPDATE_SUCCESS = 0x00;
        static const uint8_t SRUP_UPDATE_FAIL_SERVER = 0xFD;
        static const uint8_t SRUP_UPDATE_FAIL_FILE = 0xFE;
        static const uint8_t SRUP_UPDATE_FAIL_DIGEST = 0xFF;
        static const uint8_t SRUP_UPDATE_FAIL_HTTP_ERROR = 0xFC;
    }

    namespace ACTIVATE
    {
        static const uint8_t SRUP_ACTIVATE_SUCCESS = 0x10;
        static const uint8_t SRUP_ACTIVATE_FAIL = 0x1F;
    }

    namespace ACTION
    {
        static const uint8_t SRUP_ACTION_SUCCESS = 0x20;
        static const uint8_t SRUP_ACTION_UNKNOWN = 0x2E;
        static const uint8_t SRUP_ACTION_FAIL = 0x2F;
    }

    namespace DATA
    {
        static const uint8_t SRUP_DATA_TYPE_UNKNOWN = 0x3F;
    }

    namespace JOIN
    {
        static const uint8_t SRUP_JOIN_SUCCESS = 0x50;
        static const uint8_t SRUP_JOIN_REFUSED = 0x5E;
        static const uint8_t SRUP_JOIN_FAIL = 0x5F;
    }

    namespace OBSERVED_JOIN
    {
        static const uint8_t SRUP_OBSERVED_JOIN_VALID = 0x60;
        static const uint8_t SRUP_OBSERVED_JOIN_INVALID = 0x6E;
        static const uint8_t SRUP_OBSERVED_JOIN_FAIL = 0x6F;

    }

    namespace RESIGN
    {
        static const uint8_t SRUP_RESIGN_SUCCESS = 0x70;
        static const uint8_t SRUP_RESIGN_FAIL = 0x7F;
    }

    namespace DEREGISTER
    {
        static const uint8_t SRUP_DEREGISTER_SUCCESS = 0x80;
        static const uint8_t SRUP_DEREGISTER_FAIL = 0x8F;
    }
}

// For the SRUP_MSG_RESPONSE class we need to add the status field (i.e. the return value that indicates the outcome).
class SRUP_MSG_RESPONSE : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_RESPONSE();
    ~SRUP_MSG_RESPONSE() override;

    uint8_t * Serialized() override;
    bool DeSerialize(const uint8_t *) override;
    uint32_t SerializedLength() override;

    bool status(uint8_t);
    uint8_t * status();

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint8_t* m_status;


};

#endif //SRUP_LIB_SRUP_RESPONSE_H
