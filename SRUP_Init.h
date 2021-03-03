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

// The SRUP_MSG_INIT message type adds the URL of the data file & its digest.

class SRUP_MSG_INIT : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_INIT();
    ~SRUP_MSG_INIT() override;

    uint8_t* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

    bool url(const char*, uint16_t);
    char* url();
    uint16_t url_length() const;
    bool digest(const char*, uint16_t);
    char* digest();
    uint16_t digest_length() const;

protected:
    char* m_url;
    char* m_digest;

    uint16_t m_url_len;
    uint16_t m_digest_len;

    bool Serialize(bool) override;
    bool DataCheck() override;
};

#endif //SRUP_LIB_SRUP_INIT_H
