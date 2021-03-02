//
// Created by AJ Poulter on 14/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATED_DEVICE_COUNT_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATED_DEVICE_COUNT_H

#include <boost/python.hpp>
#include "SRUP_Syndicated_Device_Count.h"

void set_count_dev_count(SRUP_MSG_SYNDICATED_DEV_COUNT&, uint32_t);
boost::python::object get_count_dev_count(SRUP_MSG_SYNDICATED_DEV_COUNT&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATED_DEVICE_COUNT_H
