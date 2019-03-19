//
// Created by AJ Poulter on 14/11/2017.
//

#include "pySRUP_Response.h"

void set_status(SRUP_MSG_RESPONSE& self, uint8_t status)
{
    self.status(status);
}

// Note that since .status() can return a nullptr for an uninitialized object - we need the more complex form of
// the getter to return a None in those cases.

boost::python::object get_status(SRUP_MSG_RESPONSE& self)
{
        const uint8_t* rv;
        rv = self.status();

        if (rv != nullptr)
            return boost::python::object(*rv);
        else
            return boost::python::object();
}

// Now we'll include all of the response status values as properties...
uint8_t srup_response_status_update_success(SRUP_MSG_RESPONSE& self)
{
    return SRUP::UPDATE::SRUP_UPDATE_SUCCESS;
}

uint8_t srup_response_status_update_fail_server(SRUP_MSG_RESPONSE& self)
{
    return SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER;
}

uint8_t srup_response_status_update_fail_file(SRUP_MSG_RESPONSE& self)
{
    return SRUP::UPDATE::SRUP_UPDATE_FAIL_FILE;
}

uint8_t srup_response_status_update_fail_digest(SRUP_MSG_RESPONSE& self)
{
    return SRUP::UPDATE::SRUP_UPDATE_FAIL_DIGEST;
}

uint8_t srup_response_status_update_fail_http_error(SRUP_MSG_RESPONSE& self)
{
    return SRUP::UPDATE::SRUP_UPDATE_FAIL_HTTP_ERROR;
}

uint8_t srup_response_status_activate_success(SRUP_MSG_RESPONSE& self)
{
    return SRUP::ACTIVATE::SRUP_ACTIVATE_SUCCESS;
}

uint8_t srup_response_status_activate_fail(SRUP_MSG_RESPONSE& self)
{
    return SRUP::ACTIVATE::SRUP_ACTIVATE_FAIL;
}

uint8_t srup_response_status_action_success(SRUP_MSG_RESPONSE& self)
{
    return SRUP::ACTION::SRUP_ACTION_SUCCESS;
}

uint8_t srup_response_status_action_unknown(SRUP_MSG_RESPONSE& self)
{
    return SRUP::ACTION::SRUP_ACTION_UNKNOWN;
}

uint8_t srup_response_status_action_fail(SRUP_MSG_RESPONSE& self)
{
    return SRUP::ACTION::SRUP_ACTION_FAIL;
}

uint8_t srup_response_status_data_type_unknown(SRUP_MSG_RESPONSE& self)
{
    return SRUP::DATA::SRUP_DATA_TYPE_UNKNOWN;
}

uint8_t srup_response_status_join_success(SRUP_MSG_RESPONSE& self)
{
    return SRUP::JOIN::SRUP_JOIN_SUCCESS;
}

uint8_t srup_response_status_join_refused(SRUP_MSG_RESPONSE& self)
{
    return SRUP::JOIN::SRUP_JOIN_REFUSED;
}

uint8_t srup_response_status_join_fail(SRUP_MSG_RESPONSE& self)
{
    return SRUP::JOIN::SRUP_JOIN_FAIL;
}

uint8_t srup_response_status_observed_join_valid(SRUP_MSG_RESPONSE& self)
{
    return SRUP::OBSERVED_JOIN::SRUP_OBSERVED_JOIN_VALID;
}

uint8_t srup_response_status_observed_join_invalid(SRUP_MSG_RESPONSE& self)
{
    return SRUP::OBSERVED_JOIN::SRUP_OBSERVED_JOIN_INVALID;
}

uint8_t srup_response_status_observed_join_fail(SRUP_MSG_RESPONSE& self)
{
    return SRUP::OBSERVED_JOIN::SRUP_OBSERVED_JOIN_FAIL;
}

uint8_t srup_response_status_resign_success(SRUP_MSG_RESPONSE& self)
{
    return SRUP::RESIGN::SRUP_RESIGN_SUCCESS;
}

uint8_t srup_response_status_resign_fail(SRUP_MSG_RESPONSE& self)
{
    return SRUP::RESIGN::SRUP_RESIGN_FAIL;
}

uint8_t srup_response_status_deregister_success(SRUP_MSG_RESPONSE& self)
{
    return SRUP::DEREGISTER::SRUP_DEREGISTER_SUCCESS;
}

uint8_t srup_response_status_deregister_fail(SRUP_MSG_RESPONSE& self)
{
    return SRUP::DEREGISTER::SRUP_DEREGISTER_FAIL;
}