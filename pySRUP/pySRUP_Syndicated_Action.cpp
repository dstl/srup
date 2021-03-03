//
// Created by AJ Poulter on 13/11/2020.
//

#include "pySRUP_Syndicated_Action.h"

void set_target_id_action (SRUP_MSG_SYNDICATED_ACTION &self, uint64_t sender)
{
    self.targetID(&sender);
}

boost::python::object get_target_id_action (SRUP_MSG_SYNDICATED_ACTION& self)
{
    const uint64_t* rv;
    rv = self.targetID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}