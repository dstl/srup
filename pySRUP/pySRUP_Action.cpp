#include "pySRUP_Action.h"

void set_actionID(SRUP_MSG_ACTION& self, uint8_t action)
{
    self.action_ID(&action);    
}

// Note that since .action_ID() can return a nullptr for an uninitialized object - we need a more complex getter function for the Python 
// property to ensure that we return a None in those cases.

boost::python::object get_actionID(SRUP_MSG_ACTION& self)
{
    const uint8_t* rv;
    rv = self.action_ID();
    
    if (rv != nullptr)
        return boost::python::object(*rv);
    else
        return boost::python::object();
}