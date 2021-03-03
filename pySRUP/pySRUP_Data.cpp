//
// Created by AJ Poulter on 14/11/2017.
//

#include "pySRUP_Data.h"

void set_dataID(SRUP_MSG_DATA& self, const std::string& data_id)
{
    size_t length = data_id.length();
    if (length > UINT16_MAX)
        length = UINT16_MAX;

    self.data_ID((uint8_t*) data_id.c_str(), (uint16_t) length);
}

boost::python::object get_dataID(SRUP_MSG_DATA &self)
{
    const uint8_t* rv;
    rv = self.data_ID();

    if (rv != nullptr)
        return boost::python::object(std::string((char *) rv, self.data_ID_length()));
    else
        return boost::python::object();
}


void set_byte_data(SRUP_MSG_DATA& self, const std::string& data)
{
    self.data((uint8_t*) data.c_str(), (uint16_t) data.length());
}

boost::python::object get_byte_data(SRUP_MSG_DATA &self)
{
    const uint8_t* rv;
    rv = self.data();

    if (rv != nullptr)
        return boost::python::object(std::string((char *) rv, self.data_length()));
    else
        return boost::python::object();
}

void set_uint8_data(SRUP_MSG_DATA& self, uint8_t data)
{
    self.data(data);
}

boost::python::object get_uint8_data(SRUP_MSG_DATA& self)
{
    uint8_t* rv;
    rv = self.data_uint8();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}

void set_int8_data(SRUP_MSG_DATA& self, int8_t data)
{
    self.data(data);
}

boost::python::object get_int8_data(SRUP_MSG_DATA& self)
{
    int8_t* rv;
    rv = self.data_int8();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_uint16_data(SRUP_MSG_DATA& self, uint16_t data)
{
    self.data(data);
}

boost::python::object get_uint16_data(SRUP_MSG_DATA& self)
{
    uint16_t* rv;
    rv = self.data_uint16();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_int16_data(SRUP_MSG_DATA& self, int16_t data)
{
    self.data(data);
}

boost::python::object get_int16_data(SRUP_MSG_DATA& self)
{
    int16_t* rv;
    rv = self.data_int16();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_uint32_data(SRUP_MSG_DATA& self, uint32_t data)
{
    self.data(data);
}

boost::python::object get_uint32_data(SRUP_MSG_DATA& self)
{
    uint32_t* rv;
    rv = self.data_uint32();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_int32_data(SRUP_MSG_DATA& self, int32_t data)
{
    self.data(data);
}

boost::python::object get_int32_data(SRUP_MSG_DATA& self)
{
    int32_t* rv;
    rv = self.data_int32();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_uint64_data(SRUP_MSG_DATA& self, uint64_t data)
{
    self.data(data);
}

boost::python::object get_uint64_data(SRUP_MSG_DATA& self)
{
    uint64_t* rv;
    rv = self.data_uint64();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_int64_data(SRUP_MSG_DATA& self, int64_t data)
{
    self.data(data);
}

boost::python::object get_int64_data(SRUP_MSG_DATA& self)
{
    int64_t* rv;
    rv = self.data_int64();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_float_data(SRUP_MSG_DATA& self, float data)
{
    self.data(data);
}

boost::python::object get_float_data(SRUP_MSG_DATA& self)
{
    float* rv;
    rv = self.data_float();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

void set_double_data(SRUP_MSG_DATA& self, double data)
{
    self.data(data);
}

boost::python::object get_double_data(SRUP_MSG_DATA& self)
{
    double* rv;
    rv = self.data_double();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();

}

uint8_t get_srup_library_data_message_type()
{
    return SRUP::SRUP_MESSAGE_TYPE_DATA;
}