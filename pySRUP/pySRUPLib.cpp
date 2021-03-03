#include <boost/python.hpp>

// First the raw SRUP C++ Library files...
#include "pySRUP.h"
#include "SRUP_Generic.h"
#include "SRUP_Data.h"
#include "SRUP_Activate.h"
#include "SRUP_Join.h"
#include "SRUP_Observed_Base.h"
#include "SRUP_Observed_Join.h"
#include "SRUP_Observation_Req.h"
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

// Now the pySRUPLib files...
#include "pySRUP_Action.h"
#include "pySRUP_Response.h"
#include "pySRUP_Initiate.h"
#include "pySRUP_Data.h"
#include "pySRUP_Join.h"
#include "pySRUP_Observed.h"
#include "pySRUP_Syndicated_Action.h"
#include "pySRUP_Syndicated_Data.h"
#include "pySRUP_Syndicated_ID_REQ.h"
#include "pySRUP_Syndicated_Device_Count.h"
#include "pySRUP_Syndicated_Device_List.h"
#include "pySRUP_Syndicated_C2_Request.h"
#include "pySRUP_Syndication_Init.h"

BOOST_PYTHON_MODULE (pySRUPLib)
{
    // A "private" library function to get the library version...
    boost::python::def("__version", &get_srup_library_version);

    // Note that these can't be properties – as they're not really associated with any one of the types...

    // A set of "private" library functions to get the message type IDs for different types of message
    boost::python::def("__generic_message_type", &get_srup_library_generic_message_type);
    boost::python::def("__initiate_message_type", &get_srup_library_initiate_message_type);
    boost::python::def("__response_message_type", &get_srup_library_response_message_type);
    boost::python::def("__activate_message_type", &get_srup_library_activate_message_type);
    boost::python::def("__action_message_type", &get_srup_library_action_message_type);
    boost::python::def("__data_message_type", &get_srup_library_data_message_type);
    boost::python::def("__join_request_message_type", &get_srup_library_join_request_message_type);
    boost::python::def("__join_command_message_type", &get_srup_library_join_command_message_type);
    boost::python::def("__id_request_message_type", &get_srup_library_id_request_message_type);
    boost::python::def("__resign_request_message_type", &get_srup_library_resign_request_message_type);
    boost::python::def("__terminate_command_message_type", &get_srup_library_terminate_command_message_type);
    boost::python::def("__deregister_request_message_type", &get_srup_library_deregister_request_message_type);
    boost::python::def("__deregister_command_message_type", &get_srup_library_deregister_command_message_type);
    boost::python::def("__human_join_request_message_type", &get_srup_library_human_join_reqeust_message_type);
    boost::python::def("__human_join_response_message_type", &get_srup_library_human_join_response_message_type);
    boost::python::def("__observed_join_response_message_type", &get_srup_library_observed_join_response_message_type);
    boost::python::def("__observation_request_message_type", &get_srup_library_observation_request_message_type);
    boost::python::def("__observed_join_request_message_type", &get_srup_library_observed_join_request_message_type);

    boost::python::def("__syndicated_end_request_message_type", &get_srup_library_syndicated_end_request_message_type);
    boost::python::def("__syndicated_terminate_message_type", &get_srup_library_syndicated_terminate_message_type);
    boost::python::def("__syndicated_action_message_type", &get_srup_library_syndicated_action_message_type);
    boost::python::def("__syndicated_data_message_type", &get_srup_library_syndicated_data_message_type);
    boost::python::def("__syndicated_id_request_message_type", &get_srup_library_syndicated_ID_req_message_type);
    boost::python::def("__syndicated_device_count_message_type", &get_srup_library_syndicated_device_count_message_type);
    boost::python::def("__syndicated_device_list_message_type", &get_srup_library_syndicated_device_list_message_type);
    boost::python::def("__syndicated_c2_request_message_type", &get_srup_library_syndicated_c2_request_message_type);
    boost::python::def("__syndication_request_message_type", &get_srup_library_syndication_request_message_type);
    boost::python::def("__syndication_init_message_type", &get_srup_library_syndication_init_message_type);

    // Note that we will first create the base-class - which will set to non-copyable - and no_init
    // (meaning it is forced to be an abstract class...)
    boost::python::class_<SRUP_MSG, boost::noncopyable>("SRUP_Message_Base", boost::python::no_init)
            .add_property("version", &get_version)
            .add_property("msg_type", &get_msgtype)
            .add_property("token", &get_token, &set_token)
            .add_property("sequence_id", &get_sequenceID, &set_sequenceID)
            .add_property("sender_id", &get_senderID, &set_senderID)
          //.add_property("signature", &get_signature)
            .def("sign", &SRUP_MSG::SignF)
            .def("verify", &SRUP_MSG::VerifyF)
            .def("sign_keystring", &SRUP_MSG::Sign)
            .def("verify_keystring", &SRUP_MSG::Verify)
            .def("serialize", &serializer)
            .def("deserialize", &deserializer);

    // Next we'll add a base class for all of the observed join messages with an encrypted data item...
    // These are the Human Join Response, Observation Request, and Observed Join Request messages.
    // Note that we can't use a property here – since we have multiple parameters we need to pass to the function
    // (the data, a flag denoting if we're using a key file or a key string, & the key) – so we'll implement this
    // as discrete encrypt & decrypt methods.
    boost::python::class_<SRUP_MSG_OBS_BASE, boost::noncopyable, boost::python::bases<SRUP_MSG>>("SRUP_Observed_Base", boost::python::no_init)
            .def("encrypt", &set_encrypted_data)
            .def("decrypt", &get_decrypted_data)
            .def("encrypt_keystring", &set_encrypted_data_keystring)
            .def("decrypt_keystring", &get_decrypted_data_keystring);

    // We then create the action message as a subclass of the base messages... meaning we only need to add the bits
    // that are new to the subclass
    boost::python::class_<SRUP_MSG_ACTION, boost::python::bases<SRUP_MSG>>("SRUP_Action")
            .add_property("action_id", &get_actionID, &set_actionID);

    // Generic is essentially an implementable version of the base-class...
    boost::python::class_<SRUP_MSG_GENERIC, boost::python::bases<SRUP_MSG>> generic ("SRUP_Generic");

    // Activate doesn't have any additional properties over the base either...
    boost::python::class_<SRUP_MSG_ACTIVATE, boost::python::bases<SRUP_MSG>> activate ("SRUP_Activate");

    // Join Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_JOIN_REQ, boost::python::bases<SRUP_MSG>> join_request ("SRUP_Join_Request");

    // Human Join Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_HUMAN_JOIN_REQ, boost::python::bases<SRUP_MSG>> h_join_request ("SRUP_Human_Join_Request");

    // ID Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_ID_REQ, boost::python::bases<SRUP_MSG>> id_request ("SRUP_ID_Request");

    // Resign Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_RESIGN_REQ, boost::python::bases<SRUP_MSG>> resign_request ("SRUP_Resign_Request");

    // Terminate Command doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_TERMINATE_CMD, boost::python::bases<SRUP_MSG>> terminate_cmd ("SRUP_Terminate_Command");

    // Deregister Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_DEREGISTER_REQ, boost::python::bases<SRUP_MSG>> deregister_req ("SRUP_Deregister_Request");

    // Deregister Command doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_DEREGISTER_CMD, boost::python::bases<SRUP_MSG>> deregister_cmd ("SRUP_Deregister_Command");

    // Response has only one property to add – status...
    // But we'll also add all of the possible status values as read-only (getter only) properties...
    // Note: this includes responses for message types not yet implemented...
    boost::python::class_<SRUP_MSG_RESPONSE, boost::python::bases<SRUP_MSG>>("SRUP_Response")
            .add_property("status", &get_status, &set_status)
            .def("srup_response_status_update_success", &srup_response_status_update_success)
            .def("srup_response_status_update_fail_server", &srup_response_status_update_fail_server)
            .def("srup_response_status_update_fail_file", &srup_response_status_update_fail_file)
            .def("srup_response_status_update_fail_digest", &srup_response_status_update_fail_digest)
            .def("srup_response_status_update_fail_http_error", &srup_response_status_update_fail_http_error)
            .def("srup_response_status_activate_success", &srup_response_status_activate_success)
            .def("srup_response_status_activate_fail", &srup_response_status_activate_fail)
            .def("srup_response_status_action_success", &srup_response_status_action_success)
            .def("srup_response_status_action_unknown", &srup_response_status_action_unknown)
            .def("srup_response_status_action_fail", &srup_response_status_action_fail)
            .def("srup_response_status_data_type_unknown", &srup_response_status_data_type_unknown)
            .def("srup_response_status_join_success", &srup_response_status_join_success)
            .def("srup_response_status_join_refused", &srup_response_status_join_refused)
            .def("srup_response_status_join_fail", &srup_response_status_join_fail)
            .def("srup_response_status_observed_join_valid", &srup_response_status_observed_join_valid)
            .def("srup_response_status_observed_join_invalid", &srup_response_status_observed_join_invalid)
            .def("srup_response_status_observed_join_fail", &srup_response_status_observed_join_fail)
            .def("srup_response_status_resign_success", &srup_response_status_resign_success)
            .def("srup_response_status_resign_fail", &srup_response_status_resign_fail)
            .def("srup_response_status_deregister_success", &srup_response_status_deregister_success)
            .def("srup_response_status_deregister_fail", &srup_response_status_deregister_fail);

    // Initiate (note the slight naming change for Python) has the most simple properties to add...
    // (target, URL, digest)...
    boost::python::class_<SRUP_MSG_INIT, boost::python::bases<SRUP_MSG>>("SRUP_Initiate")
            .add_property("url", &get_url, &set_url)
            .add_property("digest", &get_digest, &set_digest);

    // Join Command adds a device ID...
    boost::python::class_<SRUP_MSG_JOIN_CMD, boost::python::bases<SRUP_MSG>>("SRUP_Join_Command")
            .add_property("device_id", &get_device_id_join, &set_device_id_join);

    // Observed Join Request adds an observer (device) ID...
    boost::python::class_<SRUP_MSG_OBSERVED_JOIN_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Observed_Join_Request")
            .add_property("observer_id", &get_observer_id_join, &set_observer_id_join);

    // Data is the hard one – given the number of overloaded implementations of the data type...
    boost::python::class_<SRUP_MSG_DATA, boost::python::bases<SRUP_MSG>>("SRUP_Data")
            .add_property("data_id", &get_dataID, &set_dataID)
            .add_property("bytes_data", &get_byte_data, &set_byte_data)
            .add_property("uint8_data", &get_uint8_data, &set_uint8_data)
            .add_property("int8_data", &get_int8_data, &set_int8_data)
            .add_property("uint16_data", &get_uint16_data, &set_uint16_data)
            .add_property("int16_data", &get_int16_data, &set_int16_data)
            .add_property("uint32_data", &get_uint32_data, &set_uint32_data)
            .add_property("int32_data", &get_int32_data, &set_int32_data)
            .add_property("uint64_data", &get_uint64_data, &set_uint64_data)
            .add_property("int64_data", &get_int64_data, &set_int64_data)
            .add_property("float_data", &get_float_data, &set_float_data)
            .add_property("double_data", &get_double_data, &set_double_data);

    // Next we have Human Join Response ... which adds nothing to the observed base message class...
    boost::python::class_<SRUP_MSG_HUMAN_JOIN_RESP, boost::python::bases<SRUP_MSG_OBS_BASE>> h_join_resp ("SRUP_Human_Join_Response");

    // ... and Observation Request (the observed base class + the joining device ID)
    boost::python::class_<SRUP_MSG_OBSERVE_REQ, boost::python::bases<SRUP_MSG_OBS_BASE>>("SRUP_Observation_Request")
        .add_property("joining_device_id", &get_joining_device_id, &set_joining_device_id);

    // ... and lastly the Observed Join Response – which adds nothing to the observed base message...
    boost::python::class_<SRUP_MSG_OBS_JOIN_RESP, boost::python::bases<SRUP_MSG_OBS_BASE>> observed_join_resp ("SRUP_Observed_Join_Response");

    // Now we'll list the syndicated / syndication classes.
    // Starting with the easy two...
    // End and Terminate don't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_SYNDICATED_TERMINATE, boost::python::bases<SRUP_MSG>> syndicated_terminate ("SRUP_Syndicated_Terminate");
    boost::python::class_<SRUP_MSG_SYNDICATED_END_REQ, boost::python::bases<SRUP_MSG>> syndicated_end ("SRUP_Syndicated_End_Request");

    // Next we'll do action, data, and ID.
    // The Syndicated ID request is the base-class plus one additional property (the target ID)...
    boost::python::class_<SRUP_MSG_SYNDICATED_ID_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Syndicated_ID_Request")
            .add_property("target_id", &get_target_id_id_req, &set_target_id_id_req);
    // The Syndicated Action is the "regular" Action class plus the target ID...
    boost::python::class_<SRUP_MSG_SYNDICATED_ACTION, boost::python::bases<SRUP_MSG_ACTION>>("SRUP_Syndicated_Action")
            .add_property("target_id", &get_target_id_action, &set_target_id_action);
    // And the Syndicated Data is the previous data class - plus a source ID.
    boost::python::class_<SRUP_MSG_SYNDICATED_DATA, boost::python::bases<SRUP_MSG_DATA>>("SRUP_Syndicated_Data")
            .add_property("source_id", &get_source_id_data, &set_source_id_data);

    // Next we'll add the device count & list message classes…
    // Device_Count adds only the count property (uint32_t)
    boost::python::class_<SRUP_MSG_SYNDICATED_DEV_COUNT, boost::python::bases<SRUP_MSG>>("SRUP_Syndicated_Device_Count")
            .add_property("count", &get_count_dev_count, &set_count_dev_count);
    // Device_List adds two properties – device_sequence and device_ID…
    boost::python::class_<SRUP_MSG_SYNDICATED_DEV_LIST, boost::python::bases<SRUP_MSG>>("SRUP_Syndicated_Device_List")
            .add_property("device_sequence", &get_sequence_dev_list, &set_sequence_dev_list)
            .add_property("device_id", &get_device_id_dev_list, &set_device_id_dev_list);
    // C2_Request is more or less the same as the data message – but it uses a request_id instead of a data id...
    // Retrospectively – we could have made design changes earlier in the process to better reuse the existing
    // data message class here... But we didn't. :-( And we can't even directly re-use the property implementations.
    // This would be quite a lot of work to refactor; but it should probably go onto the list for a future release?
    boost::python::class_<SRUP_MSG_SYNDICATED_C2_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Syndicated_C2_Request")
            .add_property("req_id", &get_reqID_c2_req, &set_reqID_c2_req)
            .add_property("bytes_data", &get_byte_c2_req, &set_byte_c2_req)
            .add_property("uint8_data", &get_uint8_c2_req, &set_uint8_c2_req)
            .add_property("int8_data", &get_int8_c2_req, &set_int8_c2_req)
            .add_property("uint16_data", &get_uint16_c2_req, &set_uint16_c2_req)
            .add_property("int16_data", &get_int16_c2_req, &set_int16_c2_req)
            .add_property("uint32_data", &get_uint32_c2_req, &set_uint32_c2_req)
            .add_property("int32_data", &get_int32_c2_req, &set_int32_c2_req)
            .add_property("uint64_data", &get_uint64_c2_req, &set_uint64_c2_req)
            .add_property("int64_data", &get_int64_c2_req, &set_int64_c2_req)
            .add_property("float_data", &get_float_c2_req, &set_float_c2_req)
            .add_property("double_data", &get_double_c2_req, &set_double_c2_req);


    // Next up for the syndication messages we have the Syndication Request...
    // For this we're using the observed base class – to provide the encrypted nonce value.
    // Syndication Request doesn't add anything new to the observed base class...
    boost::python::class_<SRUP_MSG_SYNDICATION_REQUEST, boost::python::bases<SRUP_MSG_OBS_BASE>> syndication_req ("SRUP_Syndication_Request");
    // And finally, we add the Syndication Init message – which like the syndication request, uses the observed base
    // but also adds a new property – the URL of the key service for the syndication.
    boost::python::class_<SRUP_MSG_SYNDICATION_INIT, boost::python::bases<SRUP_MSG_OBS_BASE>> ("SRUP_Syndication_Init")
            .add_property("url", &get_url_syndication_init, &set_url_syndication_init);
}
