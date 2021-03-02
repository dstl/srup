//
// Created by AJ Poulter on 02/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_DATA_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_DATA_H

#include "SRUP_Data.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_SYNDICATED_DATA = 0x25;
}

// SRUP_SYNDICATED_DATA Message

class SRUP_MSG_SYNDICATED_DATA : public  SRUP_MSG_DATA
{
    //using SRUP_MSG_DATA::SRUP_MSG_DATA;

public:
    SRUP_MSG_SYNDICATED_DATA();
    ~SRUP_MSG_SYNDICATED_DATA() override;

    const uint64_t* sourceID();
    bool sourceID(const uint64_t*);

    bool DeSerialize(const uint8_t*) override;

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;

    uint64_t* m_source_ID;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_DATA_H
