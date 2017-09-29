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
    ~SRUP_MSG_DATA();

    bool data_ID(const uint8_t*, const uint16_t);
    const uint8_t* data_ID();

    bool data(const uint8_t*, const uint16_t);
    bool data(const uint8_t);
    bool data(const int8_t);
    bool data(const uint16_t);
    bool data(const int16_t);
    bool data(const uint32_t);
    bool data(const int32_t);
    bool data(const uint64_t);
    bool data(const int64_t);
    bool data(const double);
    bool data(const float);

    const uint8_t* data();
    const uint8_t data_uint8();
    const int8_t data_int8();
    const uint16_t data_uint16();
    const int16_t data_int16();
    const uint32_t data_uint32();
    const int32_t data_int32();
    const uint64_t data_uint64();
    const int64_t data_int64();
    const float data_float();
    const double data_double();

    unsigned char* Serialized();
    bool DeSerialize(const uint8_t*);
    uint32_t SerializedLength();

protected:
    bool Serialize(bool optional = false);
    bool DataCheck();
    uint8_t* m_data_ID;
    uint8_t* m_data;
    uint16_t m_data_len;
    uint16_t m_data_ID_len;
};

#endif //SRUP_TESTS_SRUP_DATA_H
