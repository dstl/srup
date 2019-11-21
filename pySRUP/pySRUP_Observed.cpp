//
// Created by AJ Poulter on 31/05/2018.
//
#include <boost/python/errors.hpp>
#include "pySRUP_Observed.h"

void set_encrypted_data (SRUP_MSG_OBS_BASE& self, std::string s, char* keyfile)
{
    // By definition our encrypted data will be 16-bytes in length.
    // But we'll expect that for type-conversion with Python, we'll actually use a 32-character string
    // We don't need to trim it if it's longer - as the underlying method will take care of that for us
    // Given that we're specifying the length of 32 here...
    // If it's less than 32 chars – we'll pad it with 0's
    if (s.length() < 32)
        s.append(32-s.length(), 0);

    self.encrypt_data((uint8_t*) s.c_str(), s.length(), false, keyfile);
}

boost::python::object get_decrypted_data (SRUP_MSG_OBS_BASE& self, char* keyfile)
{
    const uint8_t* rv;
    rv = self.encrypted_data(false, keyfile);
    if (rv!=nullptr)
        return boost::python::object(std::string((char*)rv, 32));
    else
        return boost::python::object();
}

void set_encrypted_data_keystring (SRUP_MSG_OBS_BASE& self, std::string s, char* key)
{
    // As above, by definition our encrypted data will be 16-bytes in length.
    // But we'll expect that for type-conversion with Python, we'll actually use a 32-character string
    // We don't need to trim it if it's longer - as the underlying method will take care of that for us
    // Given that we're specifying the length of 32 here...
    // If it's less than 32 chars – we'll pad it with 0's
    if (s.length() < 32)
        s.append(32-s.length(), 0);

    self.encrypt_data((uint8_t*) s.c_str(), s.length(), true, key);
}

boost::python::object get_decrypted_data_keystring (SRUP_MSG_OBS_BASE& self, char* key)
{
    const uint8_t* rv;
    rv = self.encrypted_data(true, key);
    if (rv!=nullptr)
        return boost::python::object(std::string((char*)rv, 32));
    else
        return boost::python::object();
}