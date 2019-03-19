//
// Created by AJ Poulter on 25/05/2018.
//

#ifndef SRUP_PYSRUP_JOIN_H
#define SRUP_PYSRUP_JOIN_H

#include <boost/python.hpp>

#include "SRUP_Join_Cmd.h"
#include "SRUP_Observed_Join.h"


void set_device_id_join(SRUP_MSG_JOIN_CMD&, uint64_t);
boost::python::object get_device_id_join(SRUP_MSG_JOIN_CMD&);

void set_observer_id_join(SRUP_MSG_OBSERVED_JOIN_REQ&, uint64_t);
boost::python::object get_observer_id_join(SRUP_MSG_OBSERVED_JOIN_REQ&);

#endif //SRUP_TESTS_PYSRUP_JOIN_H
