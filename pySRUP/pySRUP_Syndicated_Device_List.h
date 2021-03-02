//
// Created by AJ Poulter on 14/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATED_DEVICE_LIST_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATED_DEVICE_LIST_H

#include <boost/python.hpp>
#include "SRUP_Syndicated_Device_List.h"

void set_sequence_dev_list(SRUP_MSG_SYNDICATED_DEV_LIST&, uint32_t);
boost::python::object get_sequence_dev_list(SRUP_MSG_SYNDICATED_DEV_LIST&);

void set_device_id_dev_list(SRUP_MSG_SYNDICATED_DEV_LIST&, uint64_t);
boost::python::object get_device_id_dev_list(SRUP_MSG_SYNDICATED_DEV_LIST&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATED_DEVICE_LIST_H
