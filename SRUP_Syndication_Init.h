//
// Created by AJ Poulter on 11/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATION_INIT_H
#define SRUP_LIBRARY_SRUP_SYNDICATION_INIT_H

#include "SRUP_Observed_Base.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_SYNDICATION_INIT = 0x21;
}

// The only thing that we need to do is define the constructor...

class SRUP_MSG_SYNDICATION_INIT : public SRUP_MSG_OBS_BASE
{
    using SRUP_MSG_OBS_BASE::SRUP_MSG_OBS_BASE;

public:
    SRUP_MSG_SYNDICATION_INIT();
    ~SRUP_MSG_SYNDICATION_INIT() override;

    bool url(const char*, uint16_t);
    char* url();
    uint16_t url_length() const;

    uint8_t* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

protected:
    char* m_url;
    uint16_t m_url_len;
    bool Serialize(bool) override;
    bool DataCheck() override;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATION_INIT_H
