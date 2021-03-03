//
// Created by AJ Poulter on 10/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_DEVICE_LIST_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_DEVICE_LIST_H
#include "SRUP.h"

namespace SRUP
{
    static uint8_t SRUP_MESSAGE_TYPE_SYNDICATED_DEV_LIST = 0x28;
}

class SRUP_MSG_SYNDICATED_DEV_LIST : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_SYNDICATED_DEV_LIST();
    ~SRUP_MSG_SYNDICATED_DEV_LIST() override;

    bool device_sequence(const uint32_t *);
    uint32_t* device_sequence();

    bool deviceID(const uint64_t *);
    uint64_t* deviceID();

    uint8_t* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint32_t* m_device_sequence;
    uint64_t* m_device_ID;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_DEVICE_LIST_H
