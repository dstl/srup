//
// Created by AJ Poulter on 13/11/2020.
//

#include "pySRUP_Syndicated_ID_REQ.h"

void set_target_id_id_req (SRUP_MSG_SYNDICATED_ID_REQ &self, uint64_t sender)
{
    self.targetID(&sender);
}

boost::python::object get_target_id_id_req (SRUP_MSG_SYNDICATED_ID_REQ& self)
{
    const uint64_t* rv;
    rv = self.targetID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}