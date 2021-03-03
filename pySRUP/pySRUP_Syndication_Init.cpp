//
// Created by AJ Poulter on 16/11/2020.
//

#include "pySRUP_Syndication_Init.h"

void set_url_syndication_init (SRUP_MSG_SYNDICATION_INIT &self, const std::string& url)
{
    // Note that we need to add one to the C++ std::string length - to allow for the terminating \0 which c_str() adds...
    self.url(url.c_str(), url.length()+1);
}

boost::python::object get_url_syndication_init (SRUP_MSG_SYNDICATION_INIT &self)
{
    const char* rv;
    rv = self.url();

    return rv != nullptr ? boost::python::object(std::string((char *) rv)) : boost::python::object();
}