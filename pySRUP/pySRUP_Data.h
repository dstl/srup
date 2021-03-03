//
// Created by AJ Poulter on 14/11/2017.
//

#ifndef SRUP_TESTS_PYSRUP_DATA_H
#define SRUP_TESTS_PYSRUP_DATA_H

#include <boost/python.hpp>
#include "SRUP_Data.h"

void set_dataID(SRUP_MSG_DATA&, const std::string&);
boost::python::object get_dataID(SRUP_MSG_DATA&);

void set_byte_data(SRUP_MSG_DATA&, const std::string&);
boost::python::object get_byte_data(SRUP_MSG_DATA&);

void set_uint8_data(SRUP_MSG_DATA&, uint8_t);
boost::python::object get_uint8_data(SRUP_MSG_DATA&);

void set_int8_data(SRUP_MSG_DATA&, int8_t);
boost::python::object get_int8_data(SRUP_MSG_DATA&);

void set_uint16_data(SRUP_MSG_DATA&, uint16_t);
boost::python::object get_uint16_data(SRUP_MSG_DATA&);

void set_int16_data(SRUP_MSG_DATA&, int16_t);
boost::python::object get_int16_data(SRUP_MSG_DATA&);

void set_uint32_data(SRUP_MSG_DATA&, uint32_t);
boost::python::object get_uint32_data(SRUP_MSG_DATA&);

void set_int32_data(SRUP_MSG_DATA&, int32_t);
boost::python::object get_int32_data(SRUP_MSG_DATA&);

void set_uint64_data(SRUP_MSG_DATA&, uint64_t);
boost::python::object get_uint64_data(SRUP_MSG_DATA&);

void set_int64_data(SRUP_MSG_DATA&, int64_t);
boost::python::object get_int64_data(SRUP_MSG_DATA&);

void set_float_data(SRUP_MSG_DATA&, float);
boost::python::object get_float_data(SRUP_MSG_DATA&);

void set_double_data(SRUP_MSG_DATA&, double);
boost::python::object get_double_data(SRUP_MSG_DATA&);

uint8_t get_srup_library_data_message_type();

#endif //SRUP_TESTS_PYSRUP_DATA_H
