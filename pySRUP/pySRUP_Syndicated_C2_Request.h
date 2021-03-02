//
// Created by AJ Poulter on 14/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATED_C2_REQUEST_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATED_C2_REQUEST_H

#include <boost/python.hpp>
#include "SRUP_Syndicated_C2_Req.h"

void set_reqID_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, uint8_t);
boost::python::object get_reqID_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_byte_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, std::string);
boost::python::object get_byte_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_uint8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, uint8_t);
boost::python::object get_uint8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_int8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, int8_t);
boost::python::object get_int8_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_uint16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, uint16_t);
boost::python::object get_uint16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_int16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, int16_t);
boost::python::object get_int16_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_uint32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, uint32_t);
boost::python::object get_uint32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_int32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, int32_t);
boost::python::object get_int32_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_uint64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, uint64_t);
boost::python::object get_uint64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_int64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, int64_t);
boost::python::object get_int64_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_float_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, float);
boost::python::object get_float_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

void set_double_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&, double);
boost::python::object get_double_c2_req(SRUP_MSG_SYNDICATED_C2_REQ&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATED_C2_REQUEST_H
