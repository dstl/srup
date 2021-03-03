//
// Created by AJ Poulter on 10/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_DEVICE_COUNT_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_DEVICE_COUNT_H
#include "SRUP.h"

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_SYNDICATED_DEV_COUNT = 0x27;
}

class SRUP_MSG_SYNDICATED_DEV_COUNT : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_SYNDICATED_DEV_COUNT();
    ~SRUP_MSG_SYNDICATED_DEV_COUNT() override;

    bool count(const uint32_t *);
    uint32_t* count();

    uint8_t* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint32_t* m_dev_count;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_DEVICE_COUNT_H
