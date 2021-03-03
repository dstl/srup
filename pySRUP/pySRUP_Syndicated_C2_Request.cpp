//
// Created by AJ Poulter on 14/11/2020.
//

#include "pySRUP_Syndicated_C2_Request.h"

void set_reqID_c2_req (SRUP_MSG_SYNDICATED_C2_REQ &self, uint8_t req_id)
{
    self.req_ID(&req_id);
}

boost::python::object get_reqID_c2_req (SRUP_MSG_SYNDICATED_C2_REQ &self)
{
    const uint8_t* rv;
    rv = self.req_ID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}

void set_byte_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, std::string data)
{
    self.data((uint8_t*) data.c_str(), (uint16_t) data.length());
}

boost::python::object get_byte_c2_req(SRUP_MSG_SYNDICATED_C2_REQ &self)
{
    const uint8_t* rv;
    rv = self.data();

    if (rv != nullptr)
        return boost::python::object(std::string((char *) rv, self.data_length()));
    else
        return boost::python::object();
}

void set_uint8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, uint8_t data)
{
    self.data(data);
}

boost::python::object get_uint8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    uint8_t* rv;
    rv = self.data_uint8();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}

void set_int8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, int8_t data)
{
    self.data(data);
}

boost::python::object get_int8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    int8_t* rv;
    rv = self.data_int8();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_uint16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, uint16_t data)
{
    self.data(data);
}

boost::python::object get_uint16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    uint16_t* rv;
    rv = self.data_uint16();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_int16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, int16_t data)
{
    self.data(data);
}

boost::python::object get_int16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    int16_t* rv;
    rv = self.data_int16();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_uint32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, uint32_t data)
{
    self.data(data);
}

boost::python::object get_uint32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    uint32_t* rv;
    rv = self.data_uint32();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_int32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, int32_t data)
{
    self.data(data);
}

boost::python::object get_int32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    int32_t* rv;
    rv = self.data_int32();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_uint64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, uint64_t data)
{
    self.data(data);
}

boost::python::object get_uint64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    uint64_t* rv;
    rv = self.data_uint64();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_int64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, int64_t data)
{
    self.data(data);
}

boost::python::object get_int64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    int64_t* rv;
    rv = self.data_int64();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_float_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, float data)
{
    self.data(data);
}

boost::python::object get_float_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    float* rv;
    rv = self.data_float();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_double_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self, double data)
{
    self.data(data);
}

boost::python::object get_double_c2_req(SRUP_MSG_SYNDICATED_C2_REQ& self)
{
    double* rv;
    rv = self.data_double();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}