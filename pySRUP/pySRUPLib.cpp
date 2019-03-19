#include <boost/python.hpp>

// First the raw SRUP C++ Library files...
#include "pySRUP.h"
#include "SRUP_Generic.h"
#include "SRUP_Data.h"
#include "SRUP_Activate.h"
#include "SRUP_Join.h"
#include "SRUP_Group_Add.h"
#include "SRUP_Group_Delete.h"
#include "SRUP_Group_Destroy.h"
#include "SRUP_Observed_Base.h"
#include "SRUP_Observed_Join.h"

// Now the pySRUPLib files...
#include "pySRUP_Action.h"
#include "pySRUP_Response.h"
#include "pySRUP_Initiate.h"
#include "pySRUP_Data.h"
#include "pySRUP_Join.h"
#include "pySRUP_Observed.h"

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
    boost::python::class_<SRUP_MSG_GENERIC, boost::python::bases<SRUP_MSG>>("SRUP_Generic");

    // Activate doesn't have any additional properties over the base either...
    boost::python::class_<SRUP_MSG_ACTIVATE, boost::python::bases<SRUP_MSG>>("SRUP_Activate");

    // Join Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_JOIN_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Join_Request");

    // Human Join Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_HUMAN_JOIN_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Human_Join_Request");

    // ID Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_ID_REQ, boost::python::bases<SRUP_MSG>>("SRUP_ID_Request");

    // Resign Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_RESIGN_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Resign_Request");

    // Terminate Command doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_TERMINATE_CMD, boost::python::bases<SRUP_MSG>>("SRUP_Terminate_Command");

    // Deregister Request doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_DEREGISTER_REQ, boost::python::bases<SRUP_MSG>>("SRUP_Deregister_Request");

    // Deregister Command doesn't have any additional properties over the base...
    boost::python::class_<SRUP_MSG_DEREGISTER_CMD, boost::python::bases<SRUP_MSG>>("SRUP_Deregister_Command");

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
    boost::python::class_<SRUP_MSG_HUMAN_JOIN_RESP, boost::python::bases<SRUP_MSG_OBS_BASE>>("SRUP_Human_Join_Response");

    // ... and Observation Request – which also adds nothing to the observed base message...
    boost::python::class_<SRUP_MSG_OBSERVE_REQ, boost::python::bases<SRUP_MSG_OBS_BASE>>("SRUP_Observation_Request");

    // ... and lastly the Observed Join Response (again - just the observed base class)
    boost::python::class_<SRUP_MSG_OBS_JOIN_RESP, boost::python::bases<SRUP_MSG_OBS_BASE>>("SRUP_Observed_Join_Response");
}
