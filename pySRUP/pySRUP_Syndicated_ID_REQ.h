//
// Created by AJ Poulter on 13/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATED_ID_REQ_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATED_ID_REQ_H

#include "SRUP_Syndicated_ID_REQ.h"
#include <boost/python.hpp>

void set_target_id_id_req(SRUP_MSG_SYNDICATED_ID_REQ&, uint64_t);
boost::python::object get_target_id_id_req(SRUP_MSG_SYNDICATED_ID_REQ&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATED_ID_REQ_H
