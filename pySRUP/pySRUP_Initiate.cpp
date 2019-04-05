//
// Created by AJ Poulter on 14/11/2017.
//

#include "pySRUP_Initiate.h"

// Note that as elsewhere as the getters can return a nullptr
// We need to use the more complex form of the getter to return a None in those cases.

void set_url(SRUP_MSG_INIT& self, std::string url)
{
    // Note that we need to add one to the C++ std::string length - to allow for the terminating \0 which c_str() adds...
    self.url(url.c_str(), url.length()+1);
}

boost::python::object get_url(SRUP_MSG_INIT& self)
{
    const char* rv;
    rv = self.url();

    if (rv != nullptr)
        return boost::python::object(std::string((char*)rv));
    else
        return boost::python::object();
}

void set_digest(SRUP_MSG_INIT& self, std::string digest)
{
    // As above we need to add one for the terminating \0...
    self.digest(digest.c_str(), digest.length()+1);
}

boost::python::object get_digest(SRUP_MSG_INIT& self)
{
    const char* rv;
    rv = self.digest();

    if (rv != nullptr)
        return boost::python::object(std::string(rv));
    else
        return boost::python::object();
}