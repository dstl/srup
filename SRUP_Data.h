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
    uint16_t data_ID_length();

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

    uint16_t data_length();

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
