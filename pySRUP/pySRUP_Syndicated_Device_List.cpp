//
// Created by AJ Poulter on 14/11/2020.
//

#include "pySRUP_Syndicated_Device_List.h"

void set_sequence_dev_list (SRUP_MSG_SYNDICATED_DEV_LIST &self, uint32_t sender)
{
    self.device_sequence(&sender);
}

boost::python::object get_sequence_dev_list (SRUP_MSG_SYNDICATED_DEV_LIST &self)
{
    const uint32_t* rv;
    rv = self.device_sequence();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}

void set_device_id_dev_list (SRUP_MSG_SYNDICATED_DEV_LIST &self, uint64_t sender)
{
    self.deviceID(&sender);
}

boost::python::object get_device_id_dev_list (SRUP_MSG_SYNDICATED_DEV_LIST &self)
{
    const uint64_t* rv;
    rv = self.deviceID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}