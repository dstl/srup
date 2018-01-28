#ifndef PY_SRUP_ACTION_H
#define PY_SRUP_ACTION_H

#include <boost/python.hpp>

#include "SRUP_Action.h"

void set_actionID(SRUP_MSG_ACTION&, uint8_t);
boost::python::object get_actionID(SRUP_MSG_ACTION&);

#endif