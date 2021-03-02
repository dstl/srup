//
// Created by AJ Poulter on 14/07/2017.
//

#ifndef SRUP_TESTS_SRUP_DATA_H
#define SRUP_TESTS_SRUP_DATA_H

#include "SRUP.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_DATA = 0x05;
}

// SRUP_DATA Message

class SRUP_MSG_DATA : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_DATA();
    ~SRUP_MSG_DATA() override;

    bool data_ID(const uint8_t*, uint16_t);
    const uint8_t* data_ID();
    uint16_t data_ID_length() const;

    bool data(const uint8_t*, uint16_t);
    bool data(uint8_t);
    bool data(int8_t);
    bool data(uint16_t);
    bool data(int16_t);
    bool data(uint32_t);
    bool data(int32_t);
    bool data(uint64_t);
    bool data(int64_t);
    bool data(double);
    bool data(float);

    const uint8_t* data();
    uint8_t* data_uint8();
    int8_t* data_int8();
    uint16_t* data_uint16();
    int16_t* data_int16();
    uint32_t* data_uint32();
    int32_t* data_int32();
    uint64_t* data_uint64();
    int64_t* data_int64();
    float* data_float();
    double* data_double();

    uint16_t data_length() const;

    unsigned char* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

protected:
    bool Serialize(bool) override;
    bool DataCheck() override;
    uint8_t* m_data_ID;
    uint8_t* m_data;
    uint16_t m_data_len;
    uint16_t m_data_ID_len;
};

#endif //SRUP_TESTS_SRUP_DATA_H
