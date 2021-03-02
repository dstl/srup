//
// Created by AJ Poulter on 13/11/2020.
//

#include "pySRUP_Syndicated_Data.h"

void set_source_id_data (SRUP_MSG_SYNDICATED_DATA &self, uint64_t sender)
{
    self.sourceID(&sender);
}

boost::python::object get_source_id_data (SRUP_MSG_SYNDICATED_DATA &self)
{const uint64_t* rv;
    rv = self.sourceID();

    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}