//
// Created by AJ Poulter on 25/05/2018.
//

#include "pySRUP_Join.h"

boost::python::object get_device_id_join(SRUP_MSG_JOIN_CMD& self)
{
    const uint64_t* rv;
    rv = self.device_ID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}


void set_device_id_join(SRUP_MSG_JOIN_CMD& self, uint64_t sender)
{
    self.device_ID(&sender);
}


boost::python::object get_observer_id_join(SRUP_MSG_OBSERVED_JOIN_REQ& self)
{
    const uint64_t* rv;
    rv = self.observer_ID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}


void set_observer_id_join(SRUP_MSG_OBSERVED_JOIN_REQ& self, uint64_t sender)
{
    self.observer_ID(&sender);
}

