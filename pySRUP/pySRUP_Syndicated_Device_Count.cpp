//
// Created by AJ Poulter on 14/11/2020.
//

#include "pySRUP_Syndicated_Device_Count.h"

void set_count_dev_count (SRUP_MSG_SYNDICATED_DEV_COUNT &self, uint32_t sender)
{
    self.count(&sender);
}

boost::python::object get_count_dev_count (SRUP_MSG_SYNDICATED_DEV_COUNT &self)
{
    const uint32_t* rv;
    rv = self.count();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}