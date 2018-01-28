//
// Created by AJ Poulter on 14/11/2017.
//

#ifndef SRUP_TESTS_PYSRUP_INITIATE_H
#define SRUP_TESTS_PYSRUP_INITIATE_H

#include "SRUP_Init.h"
#include <boost/python.hpp>
#include <string>

void set_target(SRUP_MSG_INIT&, uint64_t);
boost::python::object get_target(SRUP_MSG_INIT&);

void set_url(SRUP_MSG_INIT&, std::string);
boost::python::object get_url(SRUP_MSG_INIT&);

void set_digest(SRUP_MSG_INIT&, std::string);
boost::python::object get_digest(SRUP_MSG_INIT&);

#endif //SRUP_TESTS_PYSRUP_INITIATE_H
