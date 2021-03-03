//
// Created by AJ Poulter on 10/11/2020.
//

#ifndef SRUP_LIBRARY_SRUP_SYNDICATED_C2_REQ_H
#define SRUP_LIBRARY_SRUP_SYNDICATED_C2_REQ_H

#include "SRUP.h"

namespace SRUP
{
    static const uint8_t SRUP_MESSAGE_TYPE_SYNDICATED_C2_REQ = 0x2C;
}

// The SRUP_MESSAGE_TYPE_SYNDICATED_C2_REQ message type takes the base and adds:
//              * Request ID (uint8_t*)
//              * Request Data (variable length – see SRUP_DATA message type).
//
// Note as this is a message to the C2 server – unlike the other syndicated messages there's no source / target ID...

class SRUP_MSG_SYNDICATED_C2_REQ : public  SRUP_MSG
{
    using SRUP_MSG::SRUP_MSG;

public:
    SRUP_MSG_SYNDICATED_C2_REQ();
    ~SRUP_MSG_SYNDICATED_C2_REQ() override;

    uint8_t* Serialized() override;
    bool DeSerialize(const uint8_t*) override;
    uint32_t SerializedLength() override;

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

    uint16_t data_length();

    // Remember - *unlike* for the data messages – we're using a single byte for the request ID, rather than an
    // arbitrary string: to keep the message sizes down.
    bool req_ID(const uint8_t*);
    const uint8_t* req_ID();


protected:

    bool Serialize(bool) override;
    bool DataCheck() override;

    uint8_t* m_data;
    uint16_t m_data_len;
    uint8_t* m_req_id;
    uint16_t m_req_id_len;
};

#endif //SRUP_LIBRARY_SRUP_SYNDICATED_C2_REQ_H
