//
// Created by AJ Poulter on 31/05/2018.
//
#include <boost/python/errors.hpp>
#include "pySRUP_Observed.h"

void set_encrypted_data (SRUP_MSG_OBS_BASE& self, std::string s, char* keyfile)
{
    // By definition our encrypted data will be 16-bytes in length.
    // We don't need to trim it if it's longer - as the underlying method will take care of that for us
    // Given that we're specifying the length of 16 here...
    self.encrypted_data((uint8_t*) s.c_str(), 16, false, keyfile);
}

boost::python::object get_decrypted_data (SRUP_MSG_OBS_BASE& self, char* keyfile)
{
    const uint8_t* rv;
    rv = self.encrypted_data(false, keyfile);
    if (rv!=nullptr)
        return boost::python::object(std::string((char*)rv, 16));
    else
        return boost::python::object();
}

void set_encrypted_data_keystring (SRUP_MSG_OBS_BASE& self, std::string s, char* key)
{
    // By definition our encrypted data will be 16-bytes in length.
    // We don't need to trim it if it's longer - as the underlying method will take care of that for us
    // Given that we're specifying the length of 16 here...
    self.encrypted_data((uint8_t*) s.c_str(), 16, true, key);
}

boost::python::object get_decrypted_data_keystring (SRUP_MSG_OBS_BASE& self, char* key)
{
    const uint8_t* rv;
    rv = self.encrypted_data(true, key);
    if (rv!=nullptr)
        return boost::python::object(std::string((char*)rv, 16));
    else
        return boost::python::object();
}