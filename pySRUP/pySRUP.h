#ifndef PY_SRUP_H
#define PY_SRUP_H

#include <string>
#include <vector>

// We need boost/python to provide PyObject...
#include <boost/python.hpp>
#include <boost/python/stl_iterator.hpp>

#include "SRUP.h"
#include "SRUP_Response.h"
#include "SRUP_Generic.h"
#include "SRUP_Action.h"
#include "SRUP_Init.h"
#include "SRUP_Activate.h"

uint8_t get_srup_library_version();

uint8_t get_srup_library_generic_message_type();
uint8_t get_srup_library_initiate_message_type();
uint8_t get_srup_library_response_message_type();
uint8_t get_srup_library_activate_message_type();
uint8_t get_srup_library_action_message_type();

uint8_t get_version(SRUP_MSG&);
uint8_t get_msgtype(SRUP_MSG&);

//There should never be a need to return the raw signature in Python...
//boost::python::object get_signature(SRUP_MSG&);

boost::python::object get_token(SRUP_MSG&);
void set_token(SRUP_MSG&, std::string);

boost::python::object get_sequenceID(SRUP_MSG&);
void set_sequenceID(SRUP_MSG&, uint64_t);

boost::python::object get_senderID(SRUP_MSG&);
void set_senderID(SRUP_MSG&, uint64_t);

PyObject* serializer(SRUP_MSG&);
bool deserializer(SRUP_MSG&, boost::python::object);

#endif 