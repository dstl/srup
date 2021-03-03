//
// Created by AJ Poulter on 13/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATED_DATA_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATED_DATA_H

#include <boost/python.hpp>
#include "SRUP_Syndicated_Data.h"

void set_source_id_data(SRUP_MSG_SYNDICATED_DATA&, uint64_t);
boost::python::object get_source_id_data(SRUP_MSG_SYNDICATED_DATA&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATED_DATA_H
