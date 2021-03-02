//
// Created by AJ Poulter on 16/11/2020.
//

#ifndef SRUP_LIBRARY_PYSRUP_SYNDICATION_INIT_H
#define SRUP_LIBRARY_PYSRUP_SYNDICATION_INIT_H
#include "SRUP_Syndication_Init.h"
#include <boost/python.hpp>
#include <string>

void set_url_syndication_init(SRUP_MSG_SYNDICATION_INIT&, const std::string&);
boost::python::object get_url_syndication_init(SRUP_MSG_SYNDICATION_INIT&);

#endif //SRUP_LIBRARY_PYSRUP_SYNDICATION_INIT_H