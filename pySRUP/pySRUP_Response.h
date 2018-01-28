//
// Created by AJ Poulter on 14/11/2017.
//

#ifndef SRUP_TESTS_PYSRUP_RESPONSE_H
#define SRUP_TESTS_PYSRUP_RESPONSE_H

#include "SRUP_Response.h"
#include <boost/python.hpp>
#include <boost/python/errors.hpp>

void set_status(SRUP_MSG_RESPONSE&, uint8_t);
boost::python::object get_status(SRUP_MSG_RESPONSE&);

uint8_t srup_response_status_update_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_update_fail_server(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_update_fail_file(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_update_fail_digest(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_update_fail_http_error(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_activate_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_activate_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_action_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_action_unknown(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_action_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_data_type_unknown(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_group_add_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_group_delete_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_group_delete_invalid(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_group_delete_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_group_add_fail_limit(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_group_add_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_join_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_join_refused(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_join_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_observed_join_valid(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_observed_join_invalid(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_observed_join_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_resign_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_resign_fail(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_deregister_success(SRUP_MSG_RESPONSE&);
uint8_t srup_response_status_deregister_fail(SRUP_MSG_RESPONSE&);

#endif //SRUP_TESTS_PYSRUP_RESPONSE_H
