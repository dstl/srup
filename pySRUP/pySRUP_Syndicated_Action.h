//
// Created by AJ Poulter on 13/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATED_ACTION_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATED_ACTION_H

#include "SRUP_Syndicated_Action.h"
#include <boost/python.hpp>

void set_target_id_action(SRUP_MSG_SYNDICATED_ACTION&, uint64_t);
boost::python::object get_target_id_action(SRUP_MSG_SYNDICATED_ACTION&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATED_ACTION_H