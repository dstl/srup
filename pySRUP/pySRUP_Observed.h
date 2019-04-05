//
// Created by AJ Poulter on 25/05/2018.
//

#ifndef SRUP_PYSRUP_OBSERVED_H
#define SRUP_PYSRUP_OBSERVED_H

#include <boost/python.hpp>

#include "SRUP_Observed_Base.h"

void set_encrypted_data(SRUP_MSG_OBS_BASE&, std::string, char*);
boost::python::object get_decrypted_data(SRUP_MSG_OBS_BASE&, char*);
void set_encrypted_data_keystring(SRUP_MSG_OBS_BASE&, std::string, char*);
boost::python::object get_decrypted_data_keystring(SRUP_MSG_OBS_BASE&, char*);

#endif //SRUP_PYSRUP_OBSERVED_H
