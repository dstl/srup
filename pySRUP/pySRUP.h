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
#include "SRUP_Join.h"
#include "SRUP_Join_Cmd.h"
#include "SRUP_ID_REQ.h"
#include "SRUP_Resign.h"
#include "SRUP_Terminate.h"
#include "SRUP_Deregister.h"
#include "SRUP_Deregister_Cmd.h"
#include "SRUP_Human_Join_Resp.h"
#include "SRUP_Human_Join.h"
#include "SRUP_Observation_Req.h"
#include "SRUP_Observed_Join_Resp.h"
#include "SRUP_Observed_Join.h"
#include "SRUP_Syndicated_End_Request.h"
#include "SRUP_Syndicated_Terminate.h"
#include "SRUP_Syndicated_Data.h"
#include "SRUP_Syndicated_Action.h"
#include "SRUP_Syndicated_ID_REQ.h"
#include "SRUP_Syndicated_Device_Count.h"
#include "SRUP_Syndicated_Device_List.h"
#include "SRUP_Syndicated_C2_Req.h"
#include "SRUP_Syndication_Request.h"
#include "SRUP_Syndication_Init.h"


uint8_t get_srup_library_version();

uint8_t get_srup_library_generic_message_type();
uint8_t get_srup_library_initiate_message_type();
uint8_t get_srup_library_response_message_type();
uint8_t get_srup_library_activate_message_type();
uint8_t get_srup_library_action_message_type();
uint8_t get_srup_library_join_request_message_type();
uint8_t get_srup_library_join_command_message_type();
uint8_t get_srup_library_id_request_message_type();
uint8_t get_srup_library_resign_request_message_type();
uint8_t get_srup_library_terminate_command_message_type();
uint8_t get_srup_library_deregister_request_message_type();
uint8_t get_srup_library_deregister_command_message_type();
uint8_t get_srup_library_human_join_reqeust_message_type();
uint8_t get_srup_library_human_join_response_message_type();
uint8_t get_srup_library_observed_join_response_message_type();
uint8_t get_srup_library_observed_join_request_message_type();
uint8_t get_srup_library_observation_request_message_type();
uint8_t get_srup_library_syndicated_end_request_message_type();
uint8_t get_srup_library_syndicated_terminate_message_type();
uint8_t get_srup_library_syndicated_action_message_type();
uint8_t get_srup_library_syndicated_data_message_type();
uint8_t get_srup_library_syndicated_ID_req_message_type();
uint8_t get_srup_library_syndicated_device_count_message_type();
uint8_t get_srup_library_syndicated_device_list_message_type();
uint8_t get_srup_library_syndicated_c2_request_message_type();
uint8_t get_srup_library_syndication_request_message_type();
uint8_t get_srup_library_syndication_init_message_type();

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
