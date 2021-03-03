import pySRUPLib
import pySRUP_Exceptions

import time
import paho.mqtt.client as mqtt
import uuid
import requests
import hashlib
import os
import configparser
import ast
import re
import logging
import base64

from KeyEx_Client import KeyEx, KeyEx_C2

SRUP_GENERIC_MESSAGE_TYPE = pySRUPLib.__generic_message_type()
SRUP_ACTION_MESSAGE_TYPE = pySRUPLib.__action_message_type()
SRUP_DATA_MESSAGE_TYPE = pySRUPLib.__data_message_type()
SRUP_INITIATE_MESSAGE_TYPE = pySRUPLib.__initiate_message_type()
SRUP_RESPONSE_MESSAGE_TYPE = pySRUPLib.__response_message_type()
SRUP_ACTIVATE_MESSAGE_TYPE = pySRUPLib.__activate_message_type()
SRUP_ID_REQUEST_MESSAGE_TYPE = pySRUPLib.__id_request_message_type()
SRUP_JOIN_REQUEST_MESSAGE_TYPE = pySRUPLib.__join_request_message_type()
SRUP_HUMAN_JOIN_REQUEST_MESSAGE_TYPE = pySRUPLib.__human_join_request_message_type()
SRUP_TERMINATE_COMMAND_MESSAGE_TYPE = pySRUPLib.__terminate_command_message_type()
SRUP_JOIN_COMMAND_MESSAGE_TYPE = pySRUPLib.__join_command_message_type()
SRUP_HUMAN_JOIN_RESPONSE_MESSAGE_TYPE = pySRUPLib.__human_join_response_message_type()
SRUP_RESIGN_REQUEST_MESSAGE_TYPE = pySRUPLib.__resign_request_message_type()
SRUP_DEREGISTER_REQUEST_MESSAGE_TYPE = pySRUPLib.__deregister_request_message_type()
SRUP_DEREGISTER_COMMAND_MESSAGE_TYPE = pySRUPLib.__deregister_command_message_type()
SRUP_OBSERVED_JOIN_REQUEST_MESSAGE_TYPE = pySRUPLib.__observed_join_request_message_type()
SRUP_OBSERVED_JOIN_RESPONSE_MESSAGE_TYPE = pySRUPLib.__observed_join_response_message_type()
SRUP_OBSERVATION_REQUEST_MESSAGE_TYPE = pySRUPLib.__observation_request_message_type()

SRUP_SYNDICATION_INIT_MESSAGE_TYPE = pySRUPLib.__syndication_init_message_type()
SRUP_SYNDICATION_REQUEST_MESSAGE_TYPE = pySRUPLib.__syndication_request_message_type()
SRUP_SYNDICATED_DEVICE_COUNT_MESSAGE_TYPE = pySRUPLib.__syndicated_device_count_message_type()
SRUP_SYNDICATED_DEVICE_LIST_MESSAGE_TYPE = pySRUPLib.__syndicated_device_list_message_type()
SRUP_SYNDICATED_DATA_MESSAGE_TYPE = pySRUPLib.__syndicated_data_message_type()
SRUP_SYNDICATED_ACTION_MESSAGE_TYPE = pySRUPLib.__syndicated_action_message_type()
SRUP_SYNDICATED_ID_REQUEST_MESSAGE_TYPE = pySRUPLib.__syndicated_id_request_message_type()
SRUP_SYNDICATED_C2_REQUEST_MESSAGE_TYPE = pySRUPLib.__syndicated_c2_request_message_type()
SRUP_SYNDICATED_END_REQUEST_MESSAGE_TYPE = pySRUPLib.__syndicated_end_request_message_type()
SRUP_SYNDICATED_TERMINATE_MESSAGE_TYPE = pySRUPLib.__syndicated_terminate_message_type()

# As of the current version of the pySRUP code (changed - Feb 2019) we'll exclusively use the key-string
# rather than key file for non-local keys...
# The underpinning C++ library will continue to support both – as will the direct pySRUPLib port to Python.
# (Not least so that we can use key files for the local keys...)
# For this to work, we need to add the key to the in-memory data structure in the event of the
# JOIN, so that for any other message handler, we can assume that (for any joined device) the
# key will (should) be in the keystore.

# As of the November 2020 version we also add a class for the "syndication devices".
# This is really a special-case of a device; which is designed to "bridge" two SRUP C2 networks.
# This may also feature two networks; and/or two crypto universes (different key services and/or different
# cryptographic protocols). For the implementation in pySRUP – we'll assume that everyone is
# still using RSA; and that there are "home" and "away" key-servers. We should also enable the use of a second
# network connection (e.g. a second ethernet port, or ethernet + wifi)...
#
# We'll implement a new class for this - the SyndicationDevice – which will extend the extant Client class (which we
# will now rename to Device); but we'll set some additional "private" member variables... We'll also move away from the
# use of a boolean "isServer" flag – and instead make the determination as what we are – using isinstance() and
# comparing to the classes.
# For the syndication messages themselves, unlike with many of the previous message types – we don't need to provide
# hooks for custom handlers for all of these – since many of them are system message types and can be automatically
# handled by the library.


class SRUP:

    _keyExRoute = '/KeyEx/register/get_key/'
    _deviceTypeRoute = '/KeyEx/register/get_type/'

    def __init__(self, broker, device_id, local_private_key, local_public_key, remote_public_keys, remote_device_types,
                 start_seq_id, registration_url, chain, server_id, ca_cert, cert, key, config_filename):

        self._seq_id_dict = start_seq_id
        self._device_id = device_id
        # Strip the mqtt:// part from the broker URL
        if broker[:7] == 'mqtt://':
            broker = broker[7:]
        self._broker = broker
        self._local_private_key = local_private_key
        self._local_public_key = local_public_key

        # We'll use keystore - for any active non–local keys...
        # e.g. Any devices connected to this server, or any servers that this device is connected to.
        if remote_public_keys is None:
            self._keystore = {}
        else:
            self._keystore = remote_public_keys

        # We use a similar data structure for the device type...
        # TODO: Consider merging these two into a more complex data dictionary or database?
        if remote_device_types is None:
            self._deviceTypes = {}
        else:
            self._deviceTypes = remote_device_types

        self._ca_cert = ca_cert
        self._mqtt_cert = cert
        self._mqtt_key = key
        self._reg_url = registration_url
        self._chain = chain
        self._server_id = server_id

        self.__open_update_tokens = {}
        self._on_action = None
        self._on_data = None
        self.__on_update = None
        self.__on_update_success = None
        self.__fetch_auth = None
        self.__fetch_filename = None
        self._on_id_request = None
        self._on_terminate = None
        self._on_join_command = None
        self._on_join_request = None
        self._on_join_refused = None
        self._on_join_failed = None
        self._on_join_succeed = None
        self._on_resign_request = None
        self._on_deregister_request = None
        self._on_deregister_command = None
        self._on_human_join_request = None
        self._on_human_join_response = None
        self._on_observed_join_request = None
        self._on_observed_join_response = None
        self._on_observation_request = None
        self._on_observed_join_succeed = None
        self._on_observed_join_invalid = None
        self._on_observed_join_fail = None
        self._on_syndicated_c2_request = None
        self._on_syndicated_action = None
        self._on_syndicated_data = None
        self._on_syndicated_end_request = None
        self._on_syndicated_terminate = None

        self.__config_filename = config_filename
        self._mqtt_client = mqtt.Client(client_id="SRUP Client: {}".format(device_id))
        self._mqtt_client.on_connect = self.__on_connect
        self._mqtt_client.on_message = self._on_mqtt_message
        self._mqtt_client.tls_set(ca_certs=self._ca_cert, certfile=self._mqtt_cert, keyfile=self._mqtt_key)
        self._pySRUP_Version = lambda: "{}.{}".format(self._pySRUP_Version_major, self._pySRUP_Version_minor)
        self._pySRUP_Version_major = lambda: 2
        self._pySRUP_Version_minor = lambda: 0

        self.__observer_token = None

    def __enter__(self):
        self._mqtt_client.connect(self._broker, 8883, 60)
        self._mqtt_client.loop_start()

    def __exit__(self, *args):
        self._mqtt_client.disconnect()
        self._mqtt_client.loop_stop()

    # We'll expose a couple of internal member variables as properties...
    @property
    def server_id(self):
        return self._server_id

    @server_id.setter
    def server_id(self, sid):
        # TODO: Validate sid?...do we need to?
        self._server_id = sid

    @property
    def id(self):
        return self._device_id

    @property
    def device_keys(self):
        if isinstance(self, Server):
            return list(self._keystore)
        else:
            return []

    def _add_key_from_keyservice(self, sender, syndication=False):
        # Assuming we don't already have the key in memory; then we must fetch the key-string from the
        # keyserver (which will send it as a base64 encoded string), decode it, and then store it in the
        # dictionary - using the device ID as the key.
        hex_sender = self._convert_sender_format(sender)
        if not syndication:
            if self._chain is not None:
                r = requests.get(self._reg_url + self._keyExRoute + hex_sender, verify=self._chain)
            else:
                r = requests.get(self._reg_url + self._keyExRoute + hex_sender)
        else:
            # We're in syndication mode – so we should check we're a syndication device...
            if isinstance(self, SyndicationDevice):
                if self._syndication_chain is not None:
                    r = requests.get(self._syndication_reg_url + self._keyExRoute + hex_sender,
                                     verify=self._syndication_chain)
                else:
                    r = requests.get(self._syndication_reg_url + self._keyExRoute + hex_sender)
            else:
                # TODO: Raise custom exception...
                raise NotImplementedError

        if r.status_code == 200:
            remote_key = base64.b64decode(r.text).decode()
            self._keystore[hex_sender] = remote_key
            return True
        else:
            return False

    def _get_device_type(self, sender):
        hex_sender = self._convert_sender_format(sender)
        if self._chain is not None:
            r = requests.get(self._reg_url + self._deviceTypeRoute + hex_sender, verify=self._chain)
        else:
            r = requests.get(self._reg_url + self._deviceTypeRoute + hex_sender)
        if r.status_code == 200:
            self._deviceTypes[hex_sender] = r.text
            return True
        else:
            return False

    @staticmethod
    def _convert_sender_format(sender):
        # TODO: We might also need to do something here to ensure that we parse the "pure" hex to the typical UUID
        #       format e.g. in the format 8-4-4-4-12 such as 123e4567-e89b-12d3-a456-426655440000
        #       At least we might when we start to use newly issued IDs from the Key Service...
        if isinstance(sender, int):
            return "{:02x}".format(sender)
        elif isinstance(sender, str):
            return sender
        else:
            return None

    def _get_key(self, sender):
        hex_sender = self._convert_sender_format(sender)
        if hex_sender in self._keystore:
            return self._keystore[hex_sender]
        else:
            return None

    def _get_type(self, sender):
        hex_sender = self._convert_sender_format(sender)
        if hex_sender in self._deviceTypes:
            return self._deviceTypes[hex_sender]
        else:
            return None

    def __on_connect(self, client, userdata, flags, rc):
        # If we're a server we need to subscribe to our "server" topic - to await join requests...
        # Whereas if we're not, we need to subscribe to our "device-level" topic.
        # Although servers (probably – depending on the specific broker-side implementation) can subscribe to the
        # root SRUP topic - they shouldn't do that, to avoid receiving messages intended for other servers
        # (which on a real system could be numerous).
        if isinstance(self, Server):
            client.subscribe("SRUP/servers/{}/#".format(self._device_id), qos=1)
        else:
            client.subscribe("SRUP/{}".format(self._device_id), qos=1)
        # And sleep for a moment - just to let Paho catch-up before we move on.
        time.sleep(0.5)

    def _on_mqtt_message(self, client, userdata, msg):
        # First check if the message is even for us...
        # Remembering that server's are wild...
        topic = None
        ch_topic = msg.topic
        if ch_topic[0:5] == 'SRUP/':
            topic = ch_topic[5:]

        # First check if the message is for us (or if we're a server or SyndicationDevice read it anyway)
        if topic == self._device_id or topic == self._syndication_device_id or isinstance(self, Server):
            SRUP_generic_message = pySRUPLib.SRUP_Generic()

            # if de-serializes then it's probably a SRUP message...
            if SRUP_generic_message.deserialize(msg.payload):

                # Did we send it? If so, ignore it...
                if SRUP_generic_message.sender_id != int(self._device_id, 16):

                    # Check to see if we've had a message from this sender before (creating a counter if we haven't)
                    if SRUP_generic_message.sender_id not in self._seq_id_dict:
                        self._seq_id_dict.update({SRUP_generic_message.sender_id: 0})

                    # Get current sequence ID for this sender...
                    s = self._seq_id_dict[SRUP_generic_message.sender_id]

                    # Check to see the sequence ID of the message is greater than the last received message
                    # to avoid replay attack...
                    if SRUP_generic_message.sequence_id > s:
                        # Update the "last received" sequence ID for this sender...
                        # Get the message type of the generic message - and compare with valid message types...

                        self._seq_id_dict[SRUP_generic_message.sender_id] = SRUP_generic_message.sequence_id
                        msg_type = SRUP_generic_message.msg_type

                        if msg_type == SRUP_ACTION_MESSAGE_TYPE:
                            self._handle_action_message(msg)
                        elif msg_type == SRUP_DATA_MESSAGE_TYPE:
                            self._handle_data_message(msg)
                        elif msg_type == SRUP_INITIATE_MESSAGE_TYPE:
                            self._handle_init_message(msg)
                        elif msg_type == SRUP_RESPONSE_MESSAGE_TYPE:
                            self._handle_response_message(msg)
                        elif msg_type == SRUP_ACTIVATE_MESSAGE_TYPE:
                            self._handle_activate_message(msg)
                        elif msg_type == SRUP_ID_REQUEST_MESSAGE_TYPE:
                            self._handle_id_req_message(msg)
                        elif msg_type == SRUP_JOIN_REQUEST_MESSAGE_TYPE:
                            self._handle_join_request_message(msg)
                        elif msg_type == SRUP_TERMINATE_COMMAND_MESSAGE_TYPE:
                            self._handle_terminate_message(msg)
                        elif msg_type == SRUP_JOIN_COMMAND_MESSAGE_TYPE:
                            self._handle_join_command_message(msg)
                        elif msg_type == SRUP_RESIGN_REQUEST_MESSAGE_TYPE:
                            self._handle_resign_request_message(msg)
                        elif msg_type == SRUP_DEREGISTER_REQUEST_MESSAGE_TYPE:
                            self._handle_deregister_request_message(msg)
                        elif msg_type == SRUP_DEREGISTER_COMMAND_MESSAGE_TYPE:
                            self._handle_deregister_command_message(msg)
                        elif msg_type == SRUP_HUMAN_JOIN_REQUEST_MESSAGE_TYPE:
                            self._handle_human_join_request_message(msg)
                        elif msg_type == SRUP_HUMAN_JOIN_RESPONSE_MESSAGE_TYPE:
                            self._handle_human_join_response_message(msg)
                        elif msg_type == SRUP_OBSERVATION_REQUEST_MESSAGE_TYPE:
                            self._handle_observation_request_message(msg)
                        elif msg_type == SRUP_OBSERVED_JOIN_REQUEST_MESSAGE_TYPE:
                            self._handle_observed_join_request_message(msg)
                        elif msg_type == SRUP_OBSERVED_JOIN_RESPONSE_MESSAGE_TYPE:
                            self._handle_observed_join_response_message(msg)
                        elif msg_type == SRUP_SYNDICATION_INIT_MESSAGE_TYPE:
                            self._handle_syndication_init_message(msg)
                        elif msg_type == SRUP_SYNDICATION_REQUEST_MESSAGE_TYPE:
                            self._handle_syndication_request_message(msg)
                        elif msg_type == SRUP_SYNDICATED_DEVICE_COUNT_MESSAGE_TYPE:
                            self._handle_syndicated_device_count_message(msg)
                        elif msg_type == SRUP_SYNDICATED_DEVICE_LIST_MESSAGE_TYPE:
                            self._handle_syndicated_device_list_message(msg)
                        elif msg_type == SRUP_SYNDICATED_DATA_MESSAGE_TYPE:
                            self._handle_syndicated_data_message(msg)
                        elif msg_type == SRUP_SYNDICATED_ACTION_MESSAGE_TYPE:
                            self._handle_syndicated_action_message(msg)
                        elif msg_type == SRUP_SYNDICATED_ID_REQUEST_MESSAGE_TYPE:
                            self._handle_syndicated_id_req_message(msg)
                        elif msg_type == SRUP_SYNDICATED_C2_REQUEST_MESSAGE_TYPE:
                            self._handle_syndicated_c2_req_message(msg)
                        elif msg_type == SRUP_SYNDICATED_END_REQUEST_MESSAGE_TYPE:
                            self._handle_syndicated_end_req_message(msg)
                        elif msg_type == SRUP_SYNDICATED_TERMINATE_MESSAGE_TYPE:
                            self._handle_syndicated_terminate_message(msg)
                        else:
                            # We have received a message type that we can't handle...
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Invalid message type or format. (Message type = {}, SeqID = {})".
                                            format(format(SRUP_generic_message.msg_type, '#04x'),
                                                   SRUP_generic_message.sequence_id))

                    else:
                        # We have an invalid sequence ID...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Sequence ID 0x{:02X} is invalid".format(SRUP_generic_message.sequence_id))
                        logging.info("Sender: {}".format(hex(SRUP_generic_message.sender_id)[2:]))
                        logging.info("Message Type: {}".format(SRUP_generic_message.msg_type))
                else:
                    # This is a message that we sent – so ignore it...
                    pass

            else:
                # Message is corrupted - or otherwise didn't deserialize...
                logging.warning("Message did not deserialize...")
                # TODO: Not a SRUP Message ...
        else:
            # Not a message meant for us – so skip it...
            logging.info("Message not for this receiver")

    def _handle_action_message(self, mqtt_message):
        SRUP_action_message = pySRUPLib.SRUP_Action()
        SRUP_action_message.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_action_message.sender_id)

        if remote_key is not None:
            if SRUP_action_message.verify_keystring(remote_key):
                sender_id = "{:x}".format(SRUP_action_message.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    self._on_action(SRUP_action_message)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Action Message did not verify using stored key.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def _handle_data_message(self, mqtt_message):
        SRUP_data_message = pySRUPLib.SRUP_Data()
        SRUP_data_message.deserialize(mqtt_message.payload)

        sender = format(hex(SRUP_data_message.sender_id).lstrip('0x'))
        # We should check to see if we're a syndication device, and if this is our own message...
        if isinstance(self, SyndicationDevice):
            if sender == self._device_id or sender == self._syndication_device_id:
                return

        remote_key = self._get_key(SRUP_data_message.sender_id)
        if remote_key is not None:
            if SRUP_data_message.verify_keystring(remote_key):
                sender_id = "{:x}".format(SRUP_data_message.sender_id)
                if sender_id == self._server_id or isinstance(self, Server):
                    # We can't show the data - as we can't know what type it is...
                    logging.info("DATA MESSAGE Received – {}".format(SRUP_data_message.data_id))
                    # We now call the user's code – and we're done, unless syndication is in play...
                    self._on_data(SRUP_data_message)

                    # If we could have active syndication (e.g. if we're a server or a syndication device) and if
                    # syndication is active...
                    # (Note we have to do this as a two-part 'if' since regular devices don't have the
                    # syndication active flag – as they don't / can't know about syndication).
                    if isinstance(self, Server) or isinstance(self, SyndicationDevice):
                        if self._syndication_active:
                            # The problem we have here is that we have no idea what the underlying *type* of the data
                            # is here in the library ... Normally the user could would use the data_id to signal what
                            # the data is so that the code can use the correct method to extract the data...
                            # Given that we don't have that luxury for syndicated data; we'll use the fact that if we
                            # try to decode it as a 'string' - it'll fail if it's not one. And if so we'll assume it's
                            # a float. Clearly this may cause issue if a device on the syndicated side is actually
                            # sending integer values. But the user code in that case (in the syndicating C2 server)
                            # will be able to do some data manipulation to convert it back...
                            # e.g. int_val = struct.unpack('q', bytes(ctypes.c_double(float_val)))[0]
                            try:
                                data = SRUP_data_message.bytes_data
                            except UnicodeDecodeError:
                                data = SRUP_data_message.double_data

                            self.send_SRUP_Syndicated_Data(sender, SRUP_data_message.data_id, data)
                            logging.info("Sending Syndicated Data message to Syndication Device")

            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Data Message did not verify using stored key.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore. {}".format(sender))

    def _handle_init_message(self, mqtt_message):
        # Devices can't send init messages – so skip this if we're a server...
        if not isinstance(self, Server):
            SRUP_initiate_message = pySRUPLib.SRUP_Initiate()
            SRUP_initiate_message.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_initiate_message.sender_id)
            if remote_key is not None:
                if SRUP_initiate_message.verify_keystring(remote_key):
                    sender_id = "{:x}".format(SRUP_initiate_message.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                        self._on_initiate(SRUP_initiate_message)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Init Message did not verify using stored key.")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")

    def _handle_response_message(self, mqtt_message):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        SRUP_response_message.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_response_message.sender_id)
        if remote_key is not None:
            if SRUP_response_message.verify_keystring(remote_key):
                sender_id = "{:x}".format(SRUP_response_message.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    self._on_response(SRUP_response_message)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Response Message did not verify using stored key.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def _handle_activate_message(self, mqtt_message):
        # Devices can't send activate messages either – so again, we'll skip if we're a server.
        if not isinstance(self, Server):
            SRUP_activate_message = pySRUPLib.SRUP_Activate()
            SRUP_activate_message.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_activate_message.sender_id)
            if remote_key is not None:
                if SRUP_activate_message.verify_keystring(remote_key):
                    sender_id = "{:x}".format(SRUP_activate_message.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                        self._on_activate(SRUP_activate_message)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Activate Message did not verify using stored key")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")

    def _handle_id_req_message(self, mqtt_message):
        print("Handle ID Req Message")
        SRUP_id_request_message = pySRUPLib.SRUP_ID_Request()
        SRUP_id_request_message.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_id_request_message.sender_id)
        if remote_key is not None:
            if not SRUP_id_request_message.verify_keystring(remote_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("ID Req. Message did not verify using stored key")
            else:
                sender_id = "{:x}".format(SRUP_id_request_message.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    # If we've received an ID request message - we should call the custom handler
                    # (if we have one), or just return a default message, if we don't...
                    logging.info("ID Request Received...")
                    if self._on_id_request is None:
                        resp = "pySRUP version " + str(self._pySRUP_Version())
                    else:
                        resp = self._on_id_request()
                    logging.info("Sending Response \"{}{}\"".format(resp[:40], "..." if len(resp) > 40 else ""))
                    self.send_SRUP_Data(target_id=sender_id, data_id="IDENTIFICATION_RESPONSE", data=resp)
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def _handle_join_request_message(self, mqtt_message):
        # Devices shouldn't receive join requests - so skip if not server...
        if isinstance(self, Server):
            # Check the topic...to see if this is for us...
            if not bool(re.search('\ASRUP/servers/' + re.escape(self._device_id) + '/\w+\Z', mqtt_message.topic)):
                # TODO: THROW A CUSTOM EXCEPTION?
                # We shouldn't be subscribed to another server's "JOIN" topic – so something went a bit wrong...
                logging.debug(mqtt_message.topic)
                logging.info("Message not for this server {}".format(re.findall('\ASRUP/servers/(\w+)/\w+\Z',
                                                                                mqtt_message.topic)))
            else:
                SRUP_join_request = pySRUPLib.SRUP_Join_Request()
                SRUP_join_request.deserialize(mqtt_message.payload)

                remote_key = self._get_key(SRUP_join_request.sender_id)
                if remote_key is None:
                    # We don't already have the key – so fetch it...
                    # If we get one, proceed – if not then log the error
                    if not self._add_key_from_keyservice(SRUP_join_request.sender_id):
                        # We can't find the key at the keyserver...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Sender ({}) could not be found at KeyEx lookup service".
                                      format(self._convert_sender_format(SRUP_join_request.sender_id)))
                        return
                    else:
                        remote_key = self._get_key(SRUP_join_request.sender_id)

                # Next we need to check to see if we have the device type - as we may need this later on...
                if self._get_type(SRUP_join_request.sender_id) is None:
                    self._get_device_type(SRUP_join_request.sender_id)

                if not SRUP_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Join Request Message did not verify using stored key.")
                else:
                    joining_device = SRUP_join_request.sender_id
                    hex_joining_device = hex(joining_device).lstrip('0x')
                    logging.info("JOIN Request received from {}".format(hex_joining_device))

                    # Add the device ID & token to pending joins...
                    self._pending_joins[hex_joining_device] = SRUP_join_request.token

                    # We'll now give the "user program" the chance to accept or reject the join request...
                    # To do this, we will call the registered callback function if there is one.
                    # We'll assume that if the user hasn't registered on – then a simple join request will always be
                    # (automatically) accepted – and responded to.

                    if self._on_join_request is not None:
                        # We'll call the user's function (providing them the device ID of the device).
                        # It'll then be up to the user-code to call the .join_accept(devID) method to accept the join.
                        # They can do this using device type – which can be retrieved by using the .device_types method
                        self._on_join_request(hex_joining_device)
                    else:
                        self.accept_join(hex_joining_device)

    def _handle_human_join_request_message(self, mqtt_message):
        # Devices shouldn't receive join requests - so skip if not server...
        if isinstance(self, Server):
            # Check the topic...to see if this is for us...
            if not bool(re.search('\ASRUP/servers/' + re.escape(self._device_id) + '/\w+\Z', mqtt_message.topic)):
                # TODO: THROW A CUSTOM EXCEPTION?
                # We shouldn't be subscribed to another server's "JOIN" topic – so something went a bit wrong...
                logging.debug(mqtt_message.topic)

                logging.warning("Message not for this server {}".format(re.findall('\ASRUP/servers/(\w+)/\w+\Z',
                                                                                mqtt_message.topic)))
            else:
                SRUP_human_join_request = pySRUPLib.SRUP_Human_Join_Request()
                SRUP_human_join_request.deserialize(mqtt_message.payload)

                remote_key = self._get_key(SRUP_human_join_request.sender_id)
                if remote_key is None:
                    # We don't already have the key – so fetch it...
                    # If we get one, proceed – if not then log the error
                    if not self._add_key_from_keyservice(SRUP_human_join_request.sender_id):
                        # We can't find the key at the keyserver...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Sender ({}) could not be found at KeyEx lookup service".
                                      format(self._convert_sender_format(SRUP_human_join_request.sender_id)))
                        return
                    else:
                        remote_key = self._get_key(SRUP_human_join_request.sender_id)

                # Next we need to check to see if we have the device type - as we may need this later on...
                if self._get_type(SRUP_human_join_request.sender_id) is None:
                    self._get_device_type(SRUP_human_join_request.sender_id)

                if not SRUP_human_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Human Join Request Message did not verify using stored key.")
                else:
                    joining_device = SRUP_human_join_request.sender_id
                    hex_joining_device = hex(joining_device).lstrip('0x')
                    logging.info("HUMAN JOIN Request received from {}".format(hex_joining_device))

                    # Add the device ID & token to pending joins...
                    self._pending_joins[hex_joining_device] = SRUP_human_join_request.token

                    # We'll now give the "user program" the chance to accept or reject the join request...
                    # To do this, we will call the registered callback function if there is one.
                    # We'll assume that if the user hasn't registered on – then a simple join request will always be
                    # (automatically) accepted – and responded to.

                    if self._on_human_join_request is not None:
                        # We'll call the user's function (providing them the device ID of the device).
                        # It'll then be up to the user-code to call the .join_accept(devID) method to accept the join.
                        # They can do this using device type – which can be retrieved by using the .device_types method
                        self._on_human_join_request(hex_joining_device)
                    else:
                        # Send srup_response_status_join_fail – since we have no handler for this kind of message.
                        self.fail_join(hex_joining_device)
                        logging.warning("Human Moderated Join Message Rejected – _on_human_join_request "
                                        "is not defined.")

    def _handle_human_join_response_message(self, mqtt_message):
        SRUP_human_join_response = pySRUPLib.SRUP_Human_Join_Response()
        SRUP_human_join_response.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_human_join_response.sender_id)

        if remote_key is not None:
            if SRUP_human_join_response.verify_keystring(remote_key):
                sender_id = "{:x}".format(SRUP_human_join_response.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    if self._on_human_join_response is not None:
                        # Now we need to get the id value – using the correct key... Either our regular private key...
                        # OR our syndication identity's private key...
                        id_value = SRUP_human_join_response.decrypt(self._local_private_key)

                        if isinstance(self, SyndicationDevice) and id_value is None:
                            id_value = SRUP_human_join_response.decrypt(self._syndication_private_key)

                        if id_value is not None:
                            self._on_human_join_response(id_value)
                        else:
                            logging.error("ID Value could not be decrypted.")
                    else:
                        logging.error("Handler for Human Join Response is not defined...")
                else:
                    logging.warning("Message is from an unknown sender {} ...".format(sender_id))
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Human Join Response Message did not verify using stored key.")
        else:
            logging.warning("Key for {} not found...".format(SRUP_human_join_response.sender_id))

    def _handle_observed_join_request_message(self, mqtt_message):
        # Devices shouldn't receive join requests - so skip if not server...
        if isinstance(self, Server):
            # Check the topic...to see if this is for us...
            if not bool(re.search('\ASRUP/servers/' + re.escape(self._device_id) + '/\w+\Z', mqtt_message.topic)):
                # TODO: THROW A CUSTOM EXCEPTION?
                # We shouldn't be subscribed to another server's "JOIN" topic – so something went a bit wrong...
                logging.debug(mqtt_message.topic)
                logging.info("Message not for this server {}".format(re.findall('\ASRUP/servers/(\w+)/\w+\Z',
                                                                                mqtt_message.topic)))
            else:
                SRUP_observed_join_request = pySRUPLib.SRUP_Observed_Join_Request()
                SRUP_observed_join_request.deserialize(mqtt_message.payload)

                remote_key = self._get_key(SRUP_observed_join_request.sender_id)
                if remote_key is None:
                    # We don't already have the keyC2_Server.accept_join(pending_device, ID_req=True) – so fetch it...
                    # If we get one, proceed – if not then log the error
                    if not self._add_key_from_keyservice(SRUP_observed_join_request.sender_id):
                        # We can't find the key at the keyserver...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Sender ({}) could not be found at KeyEx lookup service".
                                      format(self._convert_sender_format(SRUP_observed_join_request.sender_id)))
                        return
                    else:
                        remote_key = self._get_key(SRUP_observed_join_request.sender_id)

                # Next we need to check to see if we have the device type - as we may need this later on...
                if self._get_type(SRUP_observed_join_request.sender_id) is None:
                    self._get_device_type(SRUP_observed_join_request.sender_id)

                if not SRUP_observed_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Observed Join Request Message did not verify using stored key.")
                else:
                    joining_device = SRUP_observed_join_request.sender_id
                    hex_joining_device = hex(joining_device).lstrip('0x')
                    logging.info("OBSERVED JOIN Request received from {}".format(hex_joining_device))

                    observer = SRUP_observed_join_request.observer_id
                    hex_observer_device = hex(observer).lstrip('0x')
                    logging.info("Device requests observer {}".format(hex_observer_device))

                    # Add the device ID & token to pending joins...
                    self._pending_joins[hex_joining_device] = SRUP_observed_join_request.token

                    # We'll now give the "user program" the chance to accept or reject the join request...
                    # To do this, we will call the registered callback function if there is one.
                    # We'll assume that if the user hasn't registered on – then a simple join request will always be
                    # (automatically) accepted – and responded to.

                    if self._on_observed_join_request is not None:
                        # We'll call the user's function (providing them the device ID of the device).
                        # It'll then be up to the user-code to call the .join_accept(devID) method to accept the join.
                        # They can do this using device type – which can be retrieved by using the .device_types method
                        self._on_observed_join_request(hex_joining_device, hex_observer_device)
                    else:
                        # Send srup_response_status_join_fail – since we have no handler for this kind of message.
                        self.fail_join(hex_joining_device)
                        logging.warning("Observed Moderated Join Message Rejected – _on_observed_join_request "
                                        "is not defined.")

    def _handle_observed_join_response_message(self, mqtt_message):
        SRUP_observed_join_response = pySRUPLib.SRUP_Observed_Join_Response()
        SRUP_observed_join_response.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_observed_join_response.sender_id)
        if remote_key is not None:
            if SRUP_observed_join_response.verify_keystring(remote_key):
                sender_id = "{:x}".format(SRUP_observed_join_response.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    if self._on_observed_join_response is not None:
                        id_value = SRUP_observed_join_response.decrypt(self._local_private_key)
                        self._on_observed_join_response(id_value)
                    else:
                        logging.error("Handler for Observed Join Response is not defined...")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Observed Join Response Message did not verify using stored key.")

    def _handle_observation_request_message(self, mqtt_message):
        SRUP_observation_request = pySRUPLib.SRUP_Observation_Request()
        SRUP_observation_request.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_observation_request.sender_id)
        if remote_key is not None:
            if SRUP_observation_request.verify_keystring(remote_key):
                sender_id = "{:x}".format(SRUP_observation_request.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    if self._on_observation_request is not None:
                        id_value = SRUP_observation_request.decrypt(self._local_private_key)
                        joining_device = SRUP_observation_request.joining_device_id
                        hex_joining_device = hex(joining_device).lstrip('0x')
                        self.__observer_token = SRUP_observation_request.token
                        self._on_observation_request(hex_joining_device, id_value)
                    else:
                        logging.error("Handler for Observation Request is not defined...")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Observation Request Message did not verify using stored key.")

    def _handle_terminate_message(self, mqtt_message):
        if not isinstance(self, Server):
            SRUP_Terminate_Command = pySRUPLib.SRUP_Terminate_Command()
            SRUP_Terminate_Command.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Terminate_Command.sender_id)
            if remote_key is not None:
                if not SRUP_Terminate_Command.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Terminate Message did not verify using stored key.")
                else:
                    sender_id = "{:x}".format(SRUP_Terminate_Command.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    # We should also call the custom handler (if we have one),
                    # or just clear our device service_id property ...
                    if self._on_terminate is None:
                        logging.info("TERMINATE Command received")
                        self._server_id = None
                    else:
                        self._on_terminate()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Server's can't handle terminate commands")

    def _handle_deregister_command_message(self, mqtt_message):
        if not isinstance(self, Server):
            SRUP_Deregister_Command = pySRUPLib.SRUP_Deregister_Command()
            SRUP_Deregister_Command.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Deregister_Command.sender_id)
            if remote_key is not None:
                if not SRUP_Deregister_Command.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Deregister Command Message did not verify using stored key.")
                else:
                    sender_id = "{:x}".format(SRUP_Deregister_Command.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    # We should also call the custom handler (if we have one),
                    # or just clear our device service_id property ...
                    if self._on_terminate is None:
                        logging.info("DEREGISTER Command received")
                        self._keystore.pop(self.server_id)
                        self._server_id = None
                    else:
                        self._on_terminate()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Server's can't handle terminate commands")

    def _handle_deregister_request_message(self, mqtt_message):
        if isinstance(self, Server):
            SRUP_Deregister_Request = pySRUPLib.SRUP_Deregister_Request()
            SRUP_Deregister_Request.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Deregister_Request.sender_id)
            if remote_key is not None:
                if not SRUP_Deregister_Request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Deregister Request Message did not verify using stored key.")
                else:
                    # Is this device, a device that we control?
                    sender_id = "{:x}".format(SRUP_Deregister_Request.sender_id)
                if isinstance(self, SyndicationDevice):
                    __synd_server_id = self._syndication_server_id
                else:
                    __synd_server_id = None
                if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                        and sender_id is not None:
                    # We should also call the custom handler (if we have one), or just remove the key...
                    if self._on_resign_request is None:
                        logging.info("DEREGISTER Request received")
                        self._controlled_devices.remove("{:x}".format(SRUP_Deregister_Request.sender_id))
                        # TODO: REMOVE KEY! (&c.)
                    else:
                        self._on_resign_request()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device's can't handle deregister requests")

    def _handle_resign_request_message(self, mqtt_message):
        if isinstance(self, Server):
            SRUP_Resign_Request = pySRUPLib.SRUP_Resign_Request()
            SRUP_Resign_Request.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Resign_Request.sender_id)
            if remote_key is not None:
                if not SRUP_Resign_Request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Resign Request Message did not verify using stored key.")
                else:
                    # Is this device, a device that we control?
                    sender_id = "{:x}".format(SRUP_Resign_Request.sender_id)
                    if isinstance(self, SyndicationDevice):
                        __synd_server_id = self._syndication_server_id
                    else:
                        __synd_server_id = None
                    if (sender_id == self._server_id or sender_id == __synd_server_id or isinstance(self, Server)) \
                            and sender_id is not None:
                        # We should also call the custom handler (if we have one),
                        # or just remove the device from the list, and drop the key...
                        if self._on_resign_request is None:
                            logging.info("RESIGN Request received")
                            self._controlled_devices.remove("{:x}".format(SRUP_Resign_Request.sender_id))
                            topic = "SRUP/{}/#".format(hex(SRUP_Resign_Request.sender_id)[2:])
                            self._mqtt_client.unsubscribe(topic)
                            logging.debug("Unsubscribed from topic {}".format(topic))
                            self._keystore.pop(self._convert_sender_format(SRUP_Resign_Request.sender_id))
                        else:
                            self._on_resign_request()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices can't handle resign requests")

    def _handle_join_command_message(self, mqtt_message):
        # For a join command - we just need to check we're not a server...
        # We shouldn't check who the server is, as it's valid to process a join command from a server that is not our
        # 'current' server...
        if not isinstance(self, Server):
            SRUP_Join_Command = pySRUPLib.SRUP_Join_Command()
            SRUP_Join_Command.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Join_Command.sender_id)

            if remote_key is None:
                # We don't have the key - so go and get it...
                if self._add_key_from_keyservice(SRUP_Join_Command.sender_id):
                    remote_key = self._get_key(SRUP_Join_Command.sender_id)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Key could not be retrieved from the key-service")
                    return

            if not SRUP_Join_Command.verify_keystring(remote_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Join Command Message did not verify using stored key.")
            else:
                # We've received a join command ...
                # We should also call the custom handler (if we have one), or just return a default
                # message, if we don't...
                if self._on_join_command is None:
                    logging.info("JOIN Command received")
                    self._server_id = "{:x}".format(SRUP_Join_Command.sender_id)
                else:
                    self._on_join_command()
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Server cannot handle join command message")

    # Next up we have handlers for the syndication message types.
    # "Normal" devices can't handle any of these – so the basic process for all of them is to check to see who we are...
    # For most message types, if we're not a syndication_device or a server – then we should ignore the message.
    #
    # The handlers are all here – so that if the wrong device receives a message – there's still a handler to log the
    # fact that the message was sent to the wrong device-type.
    # However, for syndication init and syndication request messages – there's only one type of device that can accept
    # them...syndication init is only valid for a syndication device, and syndication request is only valid for a
    # C2 server. So we'll start with these two.

    def _handle_syndication_init_message(self, mqtt_message):
        if isinstance(self, SyndicationDevice):
            self._on_syndication_init(mqtt_message=mqtt_message)
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only Syndication Devices can handle Syndication Init messages")

    def _handle_syndication_request_message(self, mqtt_message):
        SRUP_Syndication_Request = pySRUPLib.SRUP_Syndication_Request()
        SRUP_Syndication_Request.deserialize(mqtt_message.payload)
        if isinstance(self, Server):
            # We use the usual get_key – since the sender is a Syndication Device that's *joined* to this C2 server
            # in the usual way...
            remote_key = self._get_key(SRUP_Syndication_Request.sender_id)
            if remote_key is None:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Syndication Request could not be validated - sender key not found.")
            else:
                if not SRUP_Syndication_Request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Syndication Request did not verify using stored key.")
                else:
                    # There's not much else to do here – apart from calling the user's code: and the extracted ID "key"
                    # value…
                    id_value = SRUP_Syndication_Request.decrypt(self._local_private_key)
                    self._syndication_active = True
                    self._on_syndication_request(id_value, SRUP_Syndication_Request.token,
                                                 hex(SRUP_Syndication_Request.sender_id)[2:])
        else:
            # We'll check it's not our own syndication message...
            if SRUP_Syndication_Request.sender_id == int(self._syndication_device_id, 16):
                pass
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.info(SRUP_Syndication_Request.sender_id)
                logging.info(self._syndication_device_id)
                logging.warning("Only C2 Servers can handle Syndication Request messages")

    # For the other syndication message types – we just need to check that we're one or the other...

    def _handle_syndicated_device_count_message(self, mqtt_message):
        # If we're a "regular" device – this really isn't for us – and has been sent in error...
        # Remembering that SyndicationDevice is a special case of Device...
        if isinstance(self, Device) and not isinstance(self, SyndicationDevice):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated Device Count messages")

        elif isinstance(self, Server):
            SRUP_Syndicated_Dev_Count = pySRUPLib.SRUP_Syndicated_Device_Count()
            SRUP_Syndicated_Dev_Count.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Syndicated_Dev_Count.sender_id)
            if remote_key is None:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Syndicated Device Count could not be validated - sender key not found.")
            else:
                if not SRUP_Syndicated_Dev_Count.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Syndicated Device Count did not verify using stored key.")
                else:
                    # We're a server – then we need store the expected device count...
                    self._expected_syndicating_devices_count = SRUP_Syndicated_Dev_Count.count
                    self._syndication_active = True

        elif isinstance(self, SyndicationDevice):
            # We're a Syndication Device – so just forward it on
            SRUP_Syndicated_Dev_Count = pySRUPLib.SRUP_Syndicated_Device_Count()
            SRUP_Syndicated_Dev_Count.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Syndicated_Dev_Count.sender_id)
            if remote_key is None:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Syndicated Device Count could not be validated - sender key not found.")
            else:
                if not SRUP_Syndicated_Dev_Count.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Syndicated Device Count did not verify using stored key.")
                else:
                    self.send_SRUP_Syndicated_Device_Count(SRUP_Syndicated_Dev_Count.count,
                                                           SRUP_Syndicated_Dev_Count.token)

        else:
            # TODO: THROW A CUSTOM EXCEPTION
            # This should never happen – as there are only three class types...
            pass

    def _handle_syndicated_device_list_message(self, mqtt_message):
        if isinstance(self, Device) and not isinstance(self, SyndicationDevice):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated Device Count messages")
        elif isinstance(self, Server):
            SRUP_Syndicated_Dev_List = pySRUPLib.SRUP_Syndicated_Device_List()
            SRUP_Syndicated_Dev_List.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Syndicated_Dev_List.sender_id)
            if remote_key is None:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Syndicated Device List could not be validated - sender key not found.")
            else:
                if not SRUP_Syndicated_Dev_List.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Syndicated Device List did not verify using stored key.")
                else:
                    logging.info("Syndicated Device {} - {}".format(SRUP_Syndicated_Dev_List.device_sequence,
                                                                    hex(SRUP_Syndicated_Dev_List.device_id))[2:])

                    # We have a device ID & sequence - so we'll add these to the list of devices we're syndicating...
                    self._syndicating_devices[SRUP_Syndicated_Dev_List.device_sequence] =\
                        SRUP_Syndicated_Dev_List.device_id

                    # We'll also call any defined user code...
                    if self._on_syndicated_device_list is not None:
                        self._on_syndicated_device_list(SRUP_Syndicated_Dev_List.device_id)

        elif isinstance(self, SyndicationDevice):
            # We're a Syndication Device – so send it on
            SRUP_Syndicated_Dev_List = pySRUPLib.SRUP_Syndicated_Device_List()
            SRUP_Syndicated_Dev_List.deserialize(mqtt_message.payload)
            remote_key = self._get_key(SRUP_Syndicated_Dev_List.sender_id)
            if remote_key is None:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Syndicated Device List could not be validated - sender key not found.")
            else:
                if not SRUP_Syndicated_Dev_List.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Syndicated Device List did not verify using stored key.")
                else:
                    logging.info("Syndicated Device {} - {}".format(SRUP_Syndicated_Dev_List.device_sequence,
                                                                    hex(SRUP_Syndicated_Dev_List.device_id)[2:]))

            self.send_SRUP_Syndicated_Device_List(SRUP_Syndicated_Dev_List.device_sequence,
                                                  SRUP_Syndicated_Dev_List.device_id, SRUP_Syndicated_Dev_List.token)
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            # This should never happen – as there are only three class types...
            pass

    def _handle_syndicated_data_message(self, mqtt_message):
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if self._syndication_active:
                SRUP_Syndicated_Data = pySRUPLib.SRUP_Syndicated_Data()
                SRUP_Syndicated_Data.deserialize(mqtt_message.payload)

                if isinstance(self, SyndicationDevice) and \
                        SRUP_Syndicated_Data.sender_id == int(self._syndication_device_id, 16):
                    pass  # do nothing for now.
                else:
                    remote_key = self._get_key(SRUP_Syndicated_Data.sender_id)
                    if remote_key is None:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Syndicated Data Message could not be validated - sender key not found.")
                    else:
                        if not SRUP_Syndicated_Data.verify_keystring(remote_key):
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Syndicated Data Message did not verify using stored key.")
                        else:
                            # If we get here – then we need to process the message.
                            # How we do that, depends on who we are...
                            if isinstance(self, Server):
                                # If we're a server, we'll call the user's code...
                                if self._on_syndicated_data is not None:
                                    try:
                                        b_data = SRUP_Syndicated_Data.bytes_data
                                    except UnicodeDecodeError:
                                        b_data = b""

                                    self._on_syndicated_data(SRUP_Syndicated_Data.data_id,
                                                             SRUP_Syndicated_Data.source_id,
                                                             SRUP_Syndicated_Data.token, b_data,
                                                             SRUP_Syndicated_Data.double_data)
                                else:
                                    logging.error("Syndicated Action Message handler not defined.")
                            else:
                                # We're a syndication device – so here we just need to pass the message on to
                                # "our" Syndicating C2 server...
                                try:
                                    data = SRUP_Syndicated_Data.bytes_data
                                except UnicodeDecodeError:
                                    data = SRUP_Syndicated_Data.double_data

                                self.send_SRUP_Syndicated_Data(hex(SRUP_Syndicated_Data.source_id)[2:],
                                                               SRUP_Syndicated_Data.data_id, data,
                                                               SRUP_Syndicated_Data.token)

            else:
                logging.info("Syndicated Data Message received whilst Syndication is inactive.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated Data messages")

    def _handle_syndicated_action_message(self, mqtt_message):
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if self._syndication_active:
                SRUP_Syndicated_Action = pySRUPLib.SRUP_Syndicated_Action()
                SRUP_Syndicated_Action.deserialize(mqtt_message.payload)
                if isinstance(self, SyndicationDevice) and \
                        SRUP_Syndicated_Action.sender_id == int(self._syndication_device_id, 16):
                    pass  # do nothing for now.
                else:
                    remote_key = self._get_key(SRUP_Syndicated_Action.sender_id)
                    if remote_key is None:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Syndicated Action Message could not be validated - sender key not found.")
                    else:
                        if not SRUP_Syndicated_Action.verify_keystring(remote_key):
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Syndicated Action Message did not verify using stored key.")
                        else:
                            # If we get here – then we need to process the message. How we do that, depends on
                            # who we are...
                            if isinstance(self, Server):
                                # If we're a server, we'll call the user's code...
                                if self._on_syndicated_action is not None:
                                    self._on_syndicated_action(SRUP_Syndicated_Action.target_id,
                                                               SRUP_Syndicated_Action.action_id)
                                else:
                                    logging.error("Syndicated Action Message handler not defined.")
                            else:
                                # We're a syndication device – so here we just need to pass the message on to
                                # "our" Syndicating C2 server...
                                self.send_SRUP_Syndicated_Action(hex(SRUP_Syndicated_Action.target_id)[2:],
                                                                 SRUP_Syndicated_Action.action_id,
                                                                 SRUP_Syndicated_Action.token)
            else:
                logging.info("Syndicated Action Message received whilst Syndication is inactive.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated Action messages")

    def _handle_syndicated_id_req_message(self, mqtt_message):
        print("Handle Syndicated ID Req...")
        if isinstance(self, SyndicationDevice) or isinstance(self, Server):
            # We're a SyndicationDevice or a Server – so decode & verify the message...
            if self._syndication_active:
                SRUP_Syndicated_ID_Req = pySRUPLib.SRUP_Syndicated_ID_Request()
                SRUP_Syndicated_ID_Req.deserialize(mqtt_message.payload)

                if isinstance(self, SyndicationDevice) and \
                        SRUP_Syndicated_ID_Req.sender_id == int(self._syndication_device_id, 16):
                    pass  # do nothing for now.
                else:
                    remote_key = self._get_key(SRUP_Syndicated_ID_Req.sender_id)
                    if remote_key is None:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Syndicated ID Request Message could not be validated - sender key not found.")
                        logging.warning("Sender = {}".format(SRUP_Syndicated_ID_Req.sender_id))
                    else:
                        if not SRUP_Syndicated_ID_Req.verify_keystring(remote_key):
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Syndicated ID Request Message did not verify using stored key.")
                        else:
                            # If we get here – then we need to process the message.
                            # How we do that, depends on who we are...
                            if isinstance(self, Server):
                                # We'll simply forward this to the device in question...
                                # There's no real scope to run user-side code; although that could change
                                # in the future...
                                print("Sending ID Req to {}".format(hex(SRUP_Syndicated_ID_Req.target_id)[2:]))
                                self.send_SRUP_ID_Request(hex(SRUP_Syndicated_ID_Req.target_id)[2:],
                                                          SRUP_Syndicated_ID_Req.token)
                            else:
                                # We're a syndication device – so here we just need to pass the message on to
                                # "our" Syndicating C2 server...

                                self.send_SRUP_Syndicated_ID_Request_message(SRUP_Syndicated_ID_Req.target_id,
                                                                             SRUP_Syndicated_ID_Req.token)
            else:
                logging.info("Syndicated ID Request Message received whilst Syndication is inactive.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated ID Request messages")

    def _handle_syndicated_c2_req_message(self, mqtt_message):
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if self._syndication_active:
                SRUP_Syndicated_C2_Req = pySRUPLib.SRUP_Syndicated_C2_Request()
                SRUP_Syndicated_C2_Req.deserialize(mqtt_message.payload)
                if isinstance(self, SyndicationDevice) and \
                        SRUP_Syndicated_C2_Req.sender_id == int(self._syndication_device_id, 16):
                    pass  # do nothing for now.
                else:
                    remote_key = self._get_key(SRUP_Syndicated_C2_Req.sender_id)
                    if remote_key is None:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Syndicated C2 Request Message could not be validated - sender key not found.")
                    else:
                        if not SRUP_Syndicated_C2_Req.verify_keystring(remote_key):
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Syndicated C2 Request Message did not verify using stored key.")
                        else:
                            # If we get here – then we need to process the message. How we do that, depends on
                            # who we are...
                            if isinstance(self, Server):
                                # If we're a server – then we're receiving this from a Syndication device...
                                # Given that this is inherently an application-specific task, we'll simply call
                                # the user's code...
                                if self._on_syndicated_c2_request is not None:
                                    self._on_syndicated_c2_request(SRUP_Syndicated_C2_Req.req_id,
                                                                   SRUP_Syndicated_C2_Req.bytes_data)
                                else:
                                    logging.error("Syndicated C2 Request handler not defined.")
                            elif isinstance(self, SyndicationDevice):
                                # We're a syndication device – so here we just need to pass the message on to
                                # the Syndicated C2 server...
                                logging.info("Sending Syndicated C2 Request to {}".format(self._syndication_server_id))
                                self.send_SRUP_Syndicated_C2_Request_message(SRUP_Syndicated_C2_Req.req_id,
                                                                             data=SRUP_Syndicated_C2_Req.bytes_data,
                                                                             token=SRUP_Syndicated_C2_Req.token)
                            else:
                                logging.warning("Devices can't handle Syndicated C2 Requests.")
            else:
                logging.info("Syndicated C2 Request Message received whilst Syndication is inactive.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated C2 Request messages")

    def _handle_syndicated_end_req_message(self, mqtt_message):
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if self._syndication_active:
                SRUP_Syndicated_End = pySRUPLib.SRUP_Syndicated_End_Request()
                SRUP_Syndicated_End.deserialize(mqtt_message.payload)
                remote_key = self._get_key(SRUP_Syndicated_End.sender_id)
                # Check that we're not trying to process our own message!
                if isinstance(self, SyndicationDevice) and \
                        SRUP_Syndicated_End.sender_id == int(self._syndication_device_id, 16):
                    pass  # do nothing for now.
                else:
                    if remote_key is None:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Syndicated End Request Message could not be validated - sender key not found.")
                    else:
                        if not SRUP_Syndicated_End.verify_keystring(remote_key):
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Syndicated End Request Message did not verify using stored key.")
                        else:
                            # If we get here – then we need to process the message. How we do that, depends on
                            # who we are...
                            if isinstance(self, Server):
                                # If we're a server (a syndicated server sending syndication messages)
                                # – then we're receiving this from a Syndication device...
                                # e.g. The Syndicating server is asking to end the session.
                                # We'll start with a state change.
                                if self._on_syndicated_end_request is not None:
                                    self._on_syndicated_end_request()
                                self._syndication_active = False
                                self._syndication_device_id = None
                                self._syndicating_devices = {}
                                self._expected_syndicating_devices_count = None

                                # TODO: Send a response message of the correct type… (END SYNDICATION)
                            else:
                                # We're a syndication device – so here we just need to pass the message on to
                                # "our" Syndicating C2 server...
                                self.send_SRUP_Syndicated_End_Request_message(SRUP_Syndicated_End.token)
                                logging.info("Ending Syndication")
                                time.sleep(5)
                                # We'll sleep for a suitable time; and then we can disconnect from the syndicated C2
                                # We can do this ourselves, since the Syndicated Termination is not a request – but a
                                # directive that the syndication is over.
                                self._syndication_mqtt_client.disconnect()
                                self._syndication_mqtt_client.loop_stop()
                                logging.info("Disconnected from Syndicated Server")
            else:
                logging.info("Syndicated End Request Message received whilst Syndication is inactive.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated End Request messages")

    def _handle_syndicated_terminate_message(self, mqtt_message):
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if self._syndication_active:
                SRUP_Syndicated_Terminate = pySRUPLib.SRUP_Syndicated_Terminate()
                SRUP_Syndicated_Terminate.deserialize(mqtt_message.payload)
                remote_key = self._get_key(SRUP_Syndicated_Terminate.sender_id)
                if remote_key is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Syndicated Terminate Message could not be validated - sender key not found.")
                else:
                    if not SRUP_Syndicated_Terminate.verify_keystring(remote_key):
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Syndicated Terminate Message did not verify using stored key.")
                    else:
                        # If we get here – then we need to process the message. How we do that, depends on who we are...
                        if isinstance(self, Server):
                            # If we're a server (a syndicating server receiving syndication messages)
                            # – then we're receiving this notification from a Syndication device...
                            # e.g. We're just been cut off by the Syndicated C2 server.
                            # We'll call the user code; and then change the state of the syndication properties.
                            if self._on_syndicated_terminate is not None:
                                self._on_syndicated_terminate()
                            else:
                                logging.error("No Handler defined for Syndication Termination")

                            self._syndication_active = False
                            self._syndication_device_id = None
                            self._syndicating_devices = {}

                        else:
                            # We're a syndication device – so here we just need to pass the message on to
                            # "our" Syndicating C2 server...
                            self.send_SRUP_Syndicated_Terminate_message(SRUP_Syndicated_Terminate.token)
                            logging.info("Syndication Termination.")
                            time.sleep(5)

                            # We'll sleep for a suitable time; and then we can disconnect from the syndicated C2
                            # We can do this ourselves, since the Syndicated Termination is not a request – but a
                            # directive that the syndication is over.
                            self._syndication_mqtt_client.disconnect()
                            self._syndication_mqtt_client.loop_stop()
                            logging.info("Disconnected from Syndicated Server")

            else:
                logging.info("Syndicated Terminate Message received whilst Syndication is inactive.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot handle Syndicated Terminate messages")

    @staticmethod
    def _getToken():
        # Note that we wish the token to be a 128-bit UUID – rather than the 64-bit half-UUID's used for identity...
        return str(uuid.uuid4())

    def save_settings(self):
        config = configparser.ConfigParser()
        if not isinstance(self, Server):
            config["Device"] = {"identity": self._device_id,
                                "registration_url": self._reg_url}
        else:
            if self._chain is not None:
                config["Server"] = {"identity": self._device_id,
                                    "registration_url": self._reg_url,
                                    "chain": self._chain,
                                    "server_token_file": self._server_token_file}
            else:
                config["Server"] = {"identity": self._device_id,
                                    "registration_url": self._reg_url,
                                    "server_token_file": self._server_token_file}

        if not isinstance(self, Server):
            if self._server_id is None:
                server_string = ""
            else:
                server_string = self._server_id
            hex_seq_ids = {}
            for d_id, s_id in self._seq_id_dict.items():
                hex_seq_ids[self._convert_sender_format(d_id)] = s_id

            config["SRUP"] = {"broker": "mqtt://" + self._broker,
                              "server_identity": server_string,
                              "Seq_IDs": hex_seq_ids}
        else:
            hex_seq_ids = {}
            for d_id, s_id in self._seq_id_dict.items():
                hex_seq_ids[self._convert_sender_format(d_id)] = s_id

            config["SRUP"] = {"broker": "mqtt://" + self._broker,
                              "Seq_IDs": hex_seq_ids}

        remote_key_set = "{"
        for d_id, d_key in self._keystore.items():
            remote_key_set += "'{}':'{}',".format(d_id, base64.b64encode(d_key.encode()).decode())
        remote_key_set += "}"

        config["Keys"] = {"local_public": self._local_public_key,
                          "local_private": self._local_private_key,
                          "remote_keys": remote_key_set}

        if isinstance(self, Server):
            config["Devices"] = {"device_types": self._deviceTypes}

        config["Access"] = {"key": self._mqtt_key,
                            "certificate": self._mqtt_cert,
                            "ca_certificate": self._ca_cert}

        with open(self.__config_filename, 'w') as configfile:
            config.write(configfile)

    @staticmethod
    def __get_digest(filename, hasher, blocksize=65536):
        with open(filename, 'rb') as f:
            buf = f.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(blocksize)

        return hasher.hexdigest()

    def __fetch_check_file(self, url, digest, filename, auth_opts=None):
        if filename is None:
            raise pySRUP_Exceptions.SRUP_FETCHER_LOCAL_FILE_IO_ERROR
        try:
            if auth_opts is not None:
                r = requests.get(url, auth=auth_opts)
            else:
                r = requests.get(url)
            r.raise_for_status()

            with open(filename, 'wb') as f:
                f.write(r.content)

            d = self.__get_digest(filename, hashlib.sha256())

            if d == digest:
                return True,
            else:
                # delete the file...
                os.remove(filename)
                raise pySRUP_Exceptions.SRUP_FETCHER_DIGEST_ERROR

        except requests.ConnectionError:
            raise pySRUP_Exceptions.SRUP_FETCHER_SERVER_ERROR

        except requests.HTTPError:
            raise pySRUP_Exceptions.SRUP_FETCHER_FILE_ERROR

        except IOError:
            raise pySRUP_Exceptions.SRUP_FETCHER_LOCAL_FILE_IO_ERROR

    def on_action(self, f):
        self._on_action = f

    def on_data(self, f):
        self._on_data = f

    def on_update(self, f):
        self.__on_update = f

    def on_update_success(self, f):
        self.__on_update_success = f

    def on_id_request(self, f):
        self._on_id_request = f

    def on_terminate(self, f):
        self._on_terminate = f

    def on_join_command(self, f):
        self._on_join_command = f

    def on_join_request(self, f):
        self._on_join_request = f

    def on_human_join_request(self, f):
        self._on_human_join_request = f

    def on_human_join_response(self, f):
        self._on_human_join_response = f

    def on_observed_join_request(self, f):
        self._on_observed_join_request = f

    def on_observed_join_response(self, f):
        self._on_observed_join_response = f

    def on_observation_request(self, f):
        self._on_observation_request = f

    def on_join_refused(self, f):
        self._on_join_refused = f

    def on_join_failed(self, f):
        self._on_join_failed = f

    def on_join_succeed(self, f):
        self._on_join_succeed = f

    def on_observed_join_succeed(self, f):
        self._on_observed_join_succeed = f

    def on_observed_join_invalid(self, f):
        self._on_observed_join_invalid = f

    def on_observed_join_fail(self, f):
        self._on_observed_join_fail = f

    def on_resign_request(self, f):
        self._on_resign_request = f

    def on_syndicated_c2_request(self, f):
        self._on_syndicated_c2_request = f

    def on_syndicated_action(self, f):
        self._on_syndicated_action = f

    def on_syndicated_data(self, f):
        self._on_syndicated_data = f

    def on_syndicated_end_request(self, f):
        self._on_syndicated_end_request = f

    def on_syndicated_terminate(self, f):
        self._on_syndicated_terminate = f

    def update_fetch_auth(self, a):
        self.__fetch_auth = a

    def update_filename(self, f):
        self.__fetch_filename = f

    def _on_initiate(self, SRUP_initiate_message):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        status = None
        try:
            self.__fetch_check_file(SRUP_initiate_message.url, SRUP_initiate_message.digest,
                                    self.__fetch_filename, self.__fetch_auth)
        except pySRUP_Exceptions.SRUP_FETCHER_DIGEST_ERROR:
            status = SRUP_response_message.srup_response_status_update_fail_digest()
        except pySRUP_Exceptions.SRUP_FETCHER_SERVER_ERROR:
            status = SRUP_response_message.srup_response_status_update_fail_server()
        except pySRUP_Exceptions.SRUP_FETCHER_FILE_ERROR:
            status = SRUP_response_message.srup_response_status_update_fail_file()
        except pySRUP_Exceptions.SRUP_FETCHER_LOCAL_FILE_IO_ERROR:
            raise IOError
        else:
            status = SRUP_response_message.srup_response_status_update_success()
        finally:
            # We need to send the target id in string format...
            self.send_SRUP_Response(hex(SRUP_initiate_message.sender_id)[2:], status, SRUP_initiate_message.token)

    def _on_response(self, SRUP_response_message):
        # First of all we'll automatically handle the "update" message responses...
        # At this stage – we're only doing anything with update success messages – anything else just gets logged.
        logging.info("RESPONSE MESSAGE Received")
        if SRUP_response_message.status == SRUP_response_message.srup_response_status_update_success():
            target = hex(SRUP_response_message.sender_id)[2:]
            self.__on_update_success(token=SRUP_response_message.token, target=target)
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_update_fail_server():
            logging.warning("RESPONSE Message – Update Fail: Server")
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_update_fail_file():
            logging.warning("RESPONSE Message – Update Fail: File")
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_update_fail_digest():
            logging.warning("RESPONSE Message – Update Fail: Digest")

        # Next let's handle JOIN responses...
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_join_refused():
            logging.info("RESPONSE Message – Join Refused...")
            self._on_join_refused()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_join_fail():
            logging.info("RESPONSE Message – Join Failed...")
            self._on_join_failed()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_join_success():
            self._on_join_succeed()

        # Observed JOIN responses...
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_observed_join_valid():
            logging.info("RESPONSE Message – Observation Success")
            self._on_observed_join_succeed()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_observed_join_invalid():
            logging.info("RESPONSE Message – Observation Invalid")
            self._on_observed_join_invalid()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_observed_join_fail():
            logging.info("RESPONSE Message – Observation Fail")
            self._on_observed_join_fail()
        else:
            pass

    def _on_activate(self, SRUP_activate_message):
        # On receiving an activate message we must first check it's a valid one...
        # ...that is to say, that the token is on the list of "open" tokens that we've sent a successful reply to...
        logging.info("ACTIVATE MESSAGE Received")
        token = SRUP_activate_message.token
        sender = SRUP_activate_message.sender_id
        if sender in self.__open_update_tokens:
            if self.__open_update_tokens[sender] == token:
                self.save_settings()
                self.__on_update(self.__fetch_filename)

    def send_SRUP_Action(self, target_id, action_id):
        SRUP_action_message = pySRUPLib.SRUP_Action()
        SRUP_action_message.token = self._getToken()

        # When we're sending a message – the sender ID is obviously the device ID of the "device" (or server) that's
        # sending the message... The sequence ID should be one more than the last seq_id used in a message to / from
        # that recipient...
        iTarget = int(target_id, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_action_message.sequence_id = s
        SRUP_action_message.sender_id = int(self._device_id, 16)
        SRUP_action_message.action_id = action_id

        if not SRUP_action_message.sign(self._local_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_action_message.serialize()
            if isinstance(self, Server):
                pre_topic = target_id
            else:
                pre_topic = self._device_id
            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                self._mqtt_client.publish(topic, serial_data, qos=1)
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")

    def send_SRUP_Data(self, target_id, data_id, data):
        SRUP_data_message = pySRUPLib.SRUP_Data()
        SRUP_data_message.token = self._getToken()

        if target_id[:2] == "0x":
            target_id = target_id[2:]

        iTarget = int(target_id, 16)

        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_data_message.sequence_id = s
        if isinstance(self, SyndicationDevice):
            if target_id == self._syndication_server_id:
                SRUP_data_message.sender_id = int(self._syndication_device_id, 16)
            else:
                SRUP_data_message.sender_id = int(self._device_id, 16)
        else:
            SRUP_data_message.sender_id = int(self._device_id, 16)

        SRUP_data_message.data_id = data_id

        # When we're sending data to a SRUP receiver we can determine the correct type function to used;
        # based on the type of the Python variable being sent…
        # Noting that there are actually far-fewer types in Python that we can use – than there are in C++...
        if type(data) is int:
            SRUP_data_message.int32_data = data
        elif type(data) is float:
            # Remember Python only has double-precision floats...
            SRUP_data_message.double_data = data
        elif type(data) is str:
            SRUP_data_message.bytes_data = data

        # We can't do the converse however - so when we're getting data from the system – we must already know what
        # type it is: based on it's data_id...

        # Before we sign it – we need to check if we're a syndication device...
        # If we are – then we can only send it to *our* C2 Server.
        # (This is generally true. If we're a server we can send it to any device we control including a syndication
        # device – either "ours" or one from a syndicating network. But if we're a device – regular or syndication -
        # then we can only send it to our C2 server).
        if isinstance(self, SyndicationDevice):
            if target_id == self._syndication_server_id:
                key = self._syndication_private_key
            elif target_id == self._server_id:
                key = self._local_private_key
            else:
                key = None
                logging.error("Target Device ID is unknown.")
        else:
            key = self._local_private_key

        if key is None:
            logging.error("Unable to identify valid signing key...")

        if SRUP_data_message.sign(key):
            serial_data = SRUP_data_message.serialize()
            if isinstance(self, Server):
                pre_topic = target_id
            else:
                if isinstance(self, SyndicationDevice):
                    if target_id == self._syndication_server_id:
                        pre_topic = self._syndication_device_id
                    else:
                        pre_topic = self._device_id
                else:
                    pre_topic = self._device_id

            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                if isinstance(self, SyndicationDevice):
                    if target_id == self._syndication_server_id:
                        self._syndication_mqtt_client.publish(topic, serial_data, qos=1)
                    else:
                        self._mqtt_client.publish(topic, serial_data, qos=1)
                else:
                    self._mqtt_client.publish(topic, serial_data, qos=1)

                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message signing failed")

    def send_SRUP_Initiate(self, target_id, url, digest):
        SRUP_init_message = pySRUPLib.SRUP_Initiate()
        SRUP_init_message.token = self._getToken()

        iTarget = int(target_id, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_init_message.sequence_id = s
        SRUP_init_message.sender_id = int(self._device_id, 16)
        SRUP_init_message.url = url
        SRUP_init_message.digest = digest

        if not SRUP_init_message.sign(self._local_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_init_message.serialize()
            if isinstance(self, Server):
                pre_topic = target_id
            else:
                pre_topic = self._device_id

            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                self._mqtt_client.publish(topic, serial_data, qos=1)
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")

    def send_SRUP_Response(self, target_id, status, token):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        # Note that this time we need to pass in a token rather than generate one...
        SRUP_response_message.token = token

        iTarget = int(target_id, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_response_message.sequence_id = s
        SRUP_response_message.sender_id = int(self._device_id, 16)
        SRUP_response_message.status = status
        if not SRUP_response_message.sign(self._local_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_response_message.serialize()
            if isinstance(self, Server):
                pre_topic = target_id
            else:
                pre_topic = self._device_id

            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                self._mqtt_client.publish(topic, serial_data, qos=1)
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")

        # The last thing to do for an update response – is to note the token...
        if status == SRUP_response_message.srup_response_status_update_success():
            self.__open_update_tokens.update({int(target_id, 16): token})

    def send_SRUP_Activate(self, target_id, token):
        SRUP_activate_message = pySRUPLib.SRUP_Activate()
        SRUP_activate_message.token = token
        # When we're sending a message – the sender ID is obviously the device ID of the "device" (or server) that's
        # sending the message... But the sequence ID should be one more than the last seq_id used in a message to
        # that recipient...

        iTarget = int(target_id, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_activate_message.sequence_id = s
        SRUP_activate_message.sender_id = int(self._device_id, 16)
        if not SRUP_activate_message.sign(self._local_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_activate_message.serialize()
            if isinstance(self, Server):
                pre_topic = target_id
            else:
                pre_topic = self._device_id
            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                self._mqtt_client.publish(topic, serial_data, qos=1)
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")

    def send_SRUP_ID_Request(self, target_id, token=None):
        if type(target_id) is not str:
            raise ValueError

        SRUP_id_request_message = pySRUPLib.SRUP_ID_Request()
        if token is None:
            SRUP_id_request_message.token = self._getToken()
        else:
            SRUP_id_request_message.token = token

        iTarget = int(target_id, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_id_request_message.sequence_id = s
        SRUP_id_request_message.sender_id = int(self._device_id, 16)
        if not SRUP_id_request_message.sign(self._local_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_id_request_message.serialize()

            if isinstance(self, Server):
                pre_topic = target_id
            else:
                pre_topic = self._device_id

            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                self._mqtt_client.publish(topic, serial_data, qos=1)
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")

    def send_SRUP_simple_join(self):
        # Simple join is sent to the "nominated" server...received from the KeyEx service during registration
        # The identity of the server is stored in the class property __server_id
        if not isinstance(self, Server):
            SRUP_Join_Request = pySRUPLib.SRUP_Join_Request()
            SRUP_Join_Request.token = self._getToken()

            iTarget = int(self._server_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            # TODO: Fix the somewhat eccentric use of hex / int identifiers ...
            # We must also get the server's key – if we don't already have it...
            Target = self._convert_sender_format(iTarget)
            if Target not in self._keystore:
                self._add_key_from_keyservice(iTarget)

            SRUP_Join_Request.sequence_id = s
            SRUP_Join_Request.sender_id = int(self._device_id, 16)
            if not SRUP_Join_Request.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Join_Request.serialize()

                if serial_data is not None:
                    topic = "SRUP/servers/{}/{}".format(self._server_id, self._device_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending JOIN Request to {}".format(self._server_id))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't perform a join if we're a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Servers can't send join requests...")

    def send_SRUP_human_join(self):
        # As with the simple join (above) we send to the "nominated" server...
        if not isinstance(self, Server):
            SRUP_Human_Join_Request = pySRUPLib.SRUP_Human_Join_Request()
            SRUP_Human_Join_Request.token = self._getToken()
            iTarget = int(self._server_id, 16)

            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            # We must also get the server's key – if we don't already have it...
            if iTarget not in self._keystore:
                self._add_key_from_keyservice(iTarget)

            SRUP_Human_Join_Request.sequence_id = s
            SRUP_Human_Join_Request.sender_id = int(self._device_id, 16)
            if not SRUP_Human_Join_Request.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Human_Join_Request.serialize()

                if serial_data is not None:
                    topic = "SRUP/servers/{}/{}".format(self._server_id, self._device_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending HUMAN JOIN Request to {}".format(self._server_id))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't perform a join if we're a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Servers can't send human join requests...")

    def send_human_join_response(self, target_id):
        # We can only send a the HJ_resp if we're a server...
        if isinstance(self, Server):
            SRUP_HJ_Response = pySRUPLib.SRUP_Human_Join_Response()

            iTarget = int(target_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_HJ_Response.sequence_id = s
            SRUP_HJ_Response.sender_id = int(self._device_id, 16)
            SRUP_HJ_Response.token = self._getToken()

            # Generate a new UUID for the ID value
            id_val = uuid.uuid4().hex
            time.sleep(0.5)
            SRUP_HJ_Response.encrypt_keystring(id_val, self._get_key(target_id))

            if not SRUP_HJ_Response.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_HJ_Response.serialize()

                if serial_data is not None:
                    topic = "SRUP/{}".format(target_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending HUMAN JOIN RESPONSE to {}".format(target_id))
                    time.sleep(1)
                    self._pending_joins[target_id] = SRUP_HJ_Response.token
                    return id_val
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only server can send Human Join Responses...")

    def send_SRUP_observed_join(self, observer_id):
        # As with the human join (above) we send to the "nominated" server...
        if not isinstance(self, Server):
            SRUP_Observed_Join_Request = pySRUPLib.SRUP_Observed_Join_Request()
            SRUP_Observed_Join_Request.token = self._getToken()

            iTarget = int(self._server_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            # We must also get the server's key – if we don't already have it...
            if iTarget not in self._keystore:
                self._add_key_from_keyservice(iTarget)

            SRUP_Observed_Join_Request.sequence_id = s
            SRUP_Observed_Join_Request.sender_id = int(self._device_id, 16)
            SRUP_Observed_Join_Request.observer_id = int(observer_id, 16)
            if not SRUP_Observed_Join_Request.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Observed_Join_Request.serialize()

                if serial_data is not None:
                    topic = "SRUP/servers/{}/{}".format(self._server_id, self._device_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending OBSERVED JOIN Request : using Observer {}".format(observer_id))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't perform a join if we're a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Servers can't send observed join requests...")

    def send_observed_join_response(self, target_id):
        # In keeping with how things work for the human observer; we'll generate the id_val
        # (one-time key) here – and return it to the calling function... The calling function will then be
        # responsible for passing that value to the send_observation_request() function…
        # But first, check if we're a server; we can only send a the observed_join_resp if we *are* a server!
        if isinstance(self, Server):
            SRUP_Observed_Join_Response = pySRUPLib.SRUP_Observed_Join_Response()

            iTarget = int(target_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Observed_Join_Response.sequence_id = s
            SRUP_Observed_Join_Response.sender_id = int(self._device_id, 16)
            SRUP_Observed_Join_Response.token = self._getToken()

            # Generate a new UUID for the ID value
            id_val = uuid.uuid4().hex
            time.sleep(0.5)
            SRUP_Observed_Join_Response.encrypt_keystring(id_val, self._get_key(target_id))

            if not SRUP_Observed_Join_Response.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Observed_Join_Response.serialize()

                if serial_data is not None:
                    topic = "SRUP/{}".format(target_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending OBSERVED JOIN RESPONSE to {}".format(target_id))
                    time.sleep(1)
                    self._pending_joins[target_id] = SRUP_Observed_Join_Response.token
                    return id_val
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only server can send Observed Join Responses...")

    def send_observation_request(self, target_id, joining_device, id_val):
        # We can only send a the observation request if we're a server...
        if isinstance(self, Server):
            SRUP_Observation_Request = pySRUPLib.SRUP_Observation_Request()

            # The target ID here is the ID of the observer... since that's where we're sending the message...
            iTarget = int(target_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Observation_Request.sequence_id = s
            SRUP_Observation_Request.sender_id = int(self._device_id, 16)
            SRUP_Observation_Request.token = self._getToken()

            SRUP_Observation_Request.joining_device_id = int(joining_device, 16)

            if not SRUP_Observation_Request.encrypt_keystring(id_val, self._get_key(target_id)):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                SRUP_Observation_Request.sign(self._local_private_key)
                serial_data = SRUP_Observation_Request.serialize()

                if serial_data is not None:
                    topic = "SRUP/{}".format(target_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending OBSERVATION REQUEST to {}".format(target_id))
                    time.sleep(1)
                    return id_val
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Observation Request message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only server can send Observation requests...")

    def send_SRUP_Terminate(self, target_id):
        if type(target_id) is not int:
            raise ValueError

        # We can only send a terminate if we're a server...
        if isinstance(self, Server):
            # We can only send a terminate message to a device that we control...
            if target_id in self._controlled_devices:
                SRUP_Terminate_Command = pySRUPLib.SRUP_Terminate_Command()
                SRUP_Terminate_Command.token = self._getToken()

                iTarget = int(target_id, 16)
                if iTarget not in self._seq_id_dict:
                    self._seq_id_dict.update({iTarget: 0})
                self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
                s = self._seq_id_dict[iTarget]

                SRUP_Terminate_Command.sequence_id = s
                SRUP_Terminate_Command.sender_id = int(self._device_id, 16)
                if not SRUP_Terminate_Command.sign(self._local_private_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Message Signing failed")
                else:
                    serial_data = SRUP_Terminate_Command.serialize()

                    if serial_data is not None:
                        # Since we're about to terminate the device – we should remove it from the controlled_
                        # devices list. We already know it's there - as we checked earlier.
                        self._controlled_devices.remove(target_id)
                        topic = "SRUP/{}".format(target_id)
                        self._mqtt_client.publish(topic, serial_data, qos=1)
                        logging.info("Sending TERMINATE Command to {}".format(target_id))
                        time.sleep(1)
                        # Lastly we should remove the target device from our keystore...
                        self._keystore.pop(target_id)
                    else:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Only server can send terminate commands...")

    def send_SRUP_Join_Command(self, target_id):
        # We can only send a join command if we're a server...
        if isinstance(self, Server):
            # We can't send a join command to a device that we already control...
            if target_id not in self._controlled_devices:
                SRUP_Join_Command = pySRUPLib.SRUP_Join_Command()
                SRUP_Join_Command.token = self._getToken()

                iTarget = int(target_id, 16)
                if iTarget not in self._seq_id_dict:
                    self._seq_id_dict.update({iTarget: 0})
                self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
                s = self._seq_id_dict[iTarget]

                SRUP_Join_Command.sequence_id = s
                SRUP_Join_Command.sender_id = int(self._device_id, 16)
                SRUP_Join_Command.device_id = iTarget
                if not SRUP_Join_Command.sign(self._local_private_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Message Signing failed")
                else:
                    serial_data = SRUP_Join_Command.serialize()

                    if serial_data is not None:
                        # As we're adding the join we can add this to the controlled_devices list...
                        self._controlled_devices.append(target_id)
                        topic = "SRUP/{}".format(target_id)
                        self._mqtt_client.publish(topic, serial_data, qos=1)
                        logging.info("Sending JOIN Command to {}".format(target_id))
                        time.sleep(1)
                        # We also need to subscribe to the topic for the device we're just sent to...
                        self._mqtt_client.subscribe("SRUP/{}".format(target_id), qos=1)
                        # ... and add the key for this device to the keystore...
                        if not self._add_key_from_keyservice(target_id):
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.error("Device key not received from key service")
                    else:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Only servers can send join commands...")

    def send_SRUP_Resign_Request(self):
        # We can only send a resign if we're not a server...
        if not isinstance(self, Server):
            SRUP_Resign_Request = pySRUPLib.SRUP_Resign_Request()
            SRUP_Resign_Request.token = self._getToken()

            iTarget = int(self._server_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Resign_Request.sequence_id = s
            SRUP_Resign_Request.sender_id = int(self._device_id, 16)
            if not SRUP_Resign_Request.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Resign_Request.serialize()

                if serial_data is not None:
                    topic = "SRUP/{}".format(self._device_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending Resign request to server {}".format(self._server_id))

                    # As we're a device – we won't drop the server key as we can presume we might want it again in the
                    # future ... but we should clear our (current) server_id
                    self._server_id = None
                    time.sleep(1)

                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Devices cannot send resign requests...")

    def send_SRUP_Deregister_Request(self):
        # We can only send a deregister request if we're not a server...
        if not isinstance(self, Server):
            SRUP_Deregister_Request = pySRUPLib.SRUP_Deregister_Request()
            SRUP_Deregister_Request.token = self._getToken()

            iTarget = int(self._server_id, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Deregister_Request.sequence_id = s
            SRUP_Deregister_Request.sender_id = int(self._device_id, 16)
            if not SRUP_Deregister_Request.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Deregister_Request.serialize()

                if serial_data is not None:
                    topic = "SRUP/{}".format(self._device_id)
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending Deregister request to server {}".format(self._server_id))

                    # Since we're about to deregister we should clear our server_id and drop the key
                    self._keystore.pop(self.server_id)
                    self._server_id = None
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Devices cannot send deregister requests...")

    def send_SRUP_Deregister_Command(self, target_id):
        # We can only send a deregister command if we're a server...
        if isinstance(self, Server):
            # We can only send a deregister command message to a device that we control...
            if target_id in self._controlled_devices:
                SRUP_Deregister_Command = pySRUPLib.SRUP_Deregister_Command()
                SRUP_Deregister_Command.token = self._getToken()

                iTarget = int(target_id, 16)
                if iTarget not in self._seq_id_dict:
                    self._seq_id_dict.update({iTarget: 0})
                self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
                s = self._seq_id_dict[iTarget]

                SRUP_Deregister_Command.sequence_id = s
                SRUP_Deregister_Command.sender_id = int(self._device_id, 16)
                if not SRUP_Deregister_Command.sign(self._local_private_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Message Signing failed")
                else:
                    serial_data = SRUP_Deregister_Command.serialize()

                    if serial_data is not None:
                        # Since we're about to deregister the device – we should remove it from the controlled_devices
                        # list... We already know it's there - as we checked earlier.
                        self._controlled_devices.remove(target_id)
                        topic = "SRUP/{}".format(target_id)
                        self._mqtt_client.publish(topic, serial_data, qos=1)
                        logging.info("Sending DEREGISTER Command to {}".format(target_id))
                        self._keystore.pop(target_id)
                        time.sleep(1)
                    else:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only servers can send deregister commands...")

    def send_SRUP_Syndicated_Terminate_message(self, token=None):
        # We can only send a syndicated terminate if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            SRUP_Syndicated_Terminate = pySRUPLib.SRUP_Syndicated_Terminate()
            if token is None:
                SRUP_Syndicated_Terminate.token = self._getToken()
            else:
                SRUP_Syndicated_Terminate.token = token
            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send (relay) this to *our* C2 server
            #       e.g. the server ID from self._server_id...
            #
            # If we're a Syndicating C2 server – we can only send this to a syndication device...
            if isinstance(self, SyndicationDevice):
                target = self._server_id
            elif isinstance(self, Server):
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated Terminate Command – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id
            else:
                # This should be impossible to reach – since we can only get into this block if we're a
                # SyndicationDevice or a Server...
                raise TypeError

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_Terminate.sequence_id = s
            SRUP_Syndicated_Terminate.sender_id = int(self._device_id, 16)
            if not SRUP_Syndicated_Terminate.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_Terminate.serialize()
                if serial_data is not None:
                    # If we are a syndication device, we send to the server on *our* topic...
                    # ...but if we're a C2 server, we send on the *device's* topic.
                    if isinstance(self, SyndicationDevice):
                        topic = "SRUP/{}".format(self._device_id)
                    else:
                        topic = "SRUP/{}".format(self._syndication_device_id)

                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending Syndicated Terminate request to {}".format(target))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated Terminate messages...")

    def send_SRUP_Syndicated_End_Request_message(self, token=None):
        # We can only send a syndicated terminate if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            SRUP_Syndicated_End = pySRUPLib.SRUP_Syndicated_End_Request()
            # Use the token from the previous message if relevant...
            if token is None:
                SRUP_Syndicated_End.token = self._getToken()
            else:
                SRUP_Syndicated_End.token = token

            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to a (syndicated) C2 server
            # If we're a Syndicating C2 server – we can only send this to "our" syndication device...
            if isinstance(self, SyndicationDevice):
                if self._syndication_server_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated End Request – No Syndication Server ID is set.")
                    raise ValueError("No Syndication Server ID is set.")
                else:
                    target = self._syndication_server_id
            else:
                # We're a server – so our target it the syndication device
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated End Request – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_End.sequence_id = s
            if isinstance(self, Server):
                SRUP_Syndicated_End.sender_id = int(self._device_id, 16)
                key = self._local_private_key
            else:
                SRUP_Syndicated_End.sender_id = int(self._syndication_device_id, 16)
                key = self._syndication_private_key
            if not SRUP_Syndicated_End.sign(key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_End.serialize()
                if serial_data is not None:
                    # If we are a syndication device, we send to the server on *our* (syndication ID) topic...
                    # ...but if we're a C2 server, we send on the *device's* topic.
                    # Handily in this instance – for both cases, the correct value can be found in the
                    # _syndication_device_id parameter
                    topic = "SRUP/{}".format(self._syndication_device_id)

                    # However – if we're a syndication device we need to use the syndication mqtt_client and broker;
                    # rather than the usual mqtt_client / broker.
                    if isinstance(self, SyndicationDevice):
                        self._syndication_mqtt_client.publish(topic, serial_data, qos=1)
                    else:
                        self._mqtt_client.publish(topic, serial_data, qos=1)

                    logging.info("Sending Syndicated End Request to {}".format(target))
                    time.sleep(1)
                    if isinstance(self, Server):
                        # TODO: Don't change the syndication state - until we get back the response message.
                        self._syndication_active = False
                        self._syndication_device_id = None
                        self._syndicating_devices = {}
                        self._expected_syndicating_devices_count = None
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated End Request messages...")

    def send_SRUP_Syndicated_C2_Request_message(self, c2_request, data=None, token=None):
        # We can only send a syndicated C2 request if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            SRUP_Syndicated_C2_Req = pySRUPLib.SRUP_Syndicated_C2_Request()
            if token is None:
                SRUP_Syndicated_C2_Req.token = self._getToken()
            else:
                SRUP_Syndicated_C2_Req.token = token

            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to a (syndicated) C2 server
            # If we're a Syndicating C2 server – we can only send this to our syndication device...
            if isinstance(self, SyndicationDevice):
                if self._syndication_server_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndication C2 Request – No Syndicated Server ID is set.")
                    raise ValueError("No Syndication Server ID is set.")
                else:
                    target = self._syndication_server_id
            else:
                # We're a server...
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated C2 Request – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id
            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_C2_Req.sequence_id = s
            SRUP_Syndicated_C2_Req.req_id = c2_request
            if data is None:
                SRUP_Syndicated_C2_Req.int16_data = 0
            else:
                if type(data) is str:
                    SRUP_Syndicated_C2_Req.bytes_data = data
                elif type(data) is int:
                    SRUP_Syndicated_C2_Req.int16_data = data
                elif type(data) is float:
                    SRUP_Syndicated_C2_Req.double_data = data
                else:
                    logging.error("Unsupported type for Syndicated C2 data")

            if isinstance(self, Server):
                SRUP_Syndicated_C2_Req.sender_id = int(self._device_id, 16)
                key = self._local_private_key
            else:
                SRUP_Syndicated_C2_Req.sender_id = int(self._syndication_device_id, 16)
                key = self._syndication_private_key

            if not SRUP_Syndicated_C2_Req.sign(key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_C2_Req.serialize()
                if serial_data is not None:
                    # This one works the other way around to some - as it's a message from the Syndicating to
                    # the Syndicated.
                    # So if we are a syndication device, we send to the remote server on our *syndication* topic...
                    # ...but if we're a C2 server, we send on the *syndication device's* topic.
                    # Remember we never send syndication messages directly to end-user devices.
                    # This is easier than it sounds; because both can be found in self._syndication_id
                    topic = "SRUP/{}".format(self._syndication_device_id)

                    # But we do need to pick the correct interface to send it on.
                    if isinstance(self, Server):
                        self._mqtt_client.publish(topic, serial_data, qos=1)
                    else:
                        self._syndication_mqtt_client.publish(topic, serial_data, qos=1)

                    logging.info("Sending Syndicated C2 Request Message to {}".format(target))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated C2 Request messages...")

    def send_SRUP_Syndicated_Action(self, target_id, action_id, token=None):
        if type(target_id) != str:
            raise ValueError

        # We can only send a syndicated action messages if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if target_id[:2] == "0x":
                target_id = target_id[2:]
            SRUP_Syndicated_Action = pySRUPLib.SRUP_Syndicated_Action()
            if token is None:
                SRUP_Syndicated_Action.token = self._getToken()
            else:
                SRUP_Syndicated_Action.token = token

            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to a (syndicated) C2 server
            # If we're a Syndicating C2 server – we can only send this to a syndication device...
            if isinstance(self, SyndicationDevice):
                if self._syndication_server_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndication Action Message – No Syndicated Server ID is set.")
                    raise ValueError("No Syndication Server ID is set.")
                else:
                    target = self._syndication_server_id
            else:
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated Action Message – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_Action.sequence_id = s

            if isinstance(self, Server):
                SRUP_Syndicated_Action.sender_id = int(self._device_id, 16)
            else:
                SRUP_Syndicated_Action.sender_id = int(self._syndication_device_id, 16)

            SRUP_Syndicated_Action.target_id = int(target_id, 16)
            SRUP_Syndicated_Action.action_id = action_id

            if isinstance(self, SyndicationDevice):
                key = self._syndication_private_key
            else:
                key = self._local_private_key

            if not SRUP_Syndicated_Action.sign(key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_Action.serialize()
                if serial_data is not None:
                    # If we are a syndication device, we send to the server on *our* topic...
                    # ...but if we're a C2 server, we send on the *syndication device's* topic.
                    topic = "SRUP/{}".format(self._syndication_device_id)

                    if isinstance(self, SyndicationDevice):
                        self._syndication_mqtt_client.publish(topic, serial_data, qos=1)
                    else:
                        self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending Syndicated Action Message to {}".format(target))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated Action messages...")

    def send_SRUP_Syndicated_ID_Request_message(self, target_id, token=None):

        if type(target_id) is not int:
            target_id = int(target_id, 16)

        # We can only send a syndicated action messages if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):

            target_device = hex(target_id)[2:]

            SRUP_Syndicated_ID_Req = pySRUPLib.SRUP_Syndicated_ID_Request()
            if token is None:
                SRUP_Syndicated_ID_Req.token = self._getToken()
            else:
                SRUP_Syndicated_ID_Req.token = token

            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to a (syndicated) C2 server
            # If we're a Syndicating C2 server – we can only send this to a syndication device...
            if isinstance(self, SyndicationDevice):
                if self._syndication_server_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndication ID Request Message – No Syndicated Server ID is set.")
                    raise ValueError("No Syndication Server ID is set.")
                else:
                    target = self._syndication_server_id

            else:
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated ID Request Message – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_ID_Req.sequence_id = s
            if isinstance(self, Server):
                SRUP_Syndicated_ID_Req.sender_id = int(self._device_id, 16)
            else:
                SRUP_Syndicated_ID_Req.sender_id = int(self._syndication_device_id, 16)

            SRUP_Syndicated_ID_Req.target_id = target_id
            if isinstance(self, Server):
                key = self._local_private_key
            else:
                key = self._syndication_private_key

            if not SRUP_Syndicated_ID_Req.sign(key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_ID_Req.serialize()
                if serial_data is not None:
                    # If we are a syndication device, we send to the server on *our* topic...
                    if isinstance(self, SyndicationDevice):
                        topic = "SRUP/{}".format(self._syndication_device_id)

                        self._syndication_mqtt_client.publish(topic, serial_data, qos=1)
                    else:
                        topic = "SRUP/{}".format(self._syndication_device_id)
                        self._mqtt_client.publish(topic, serial_data, qos=1)

                    logging.info("Sending Syndicated ID Request Message for device {} (to {})".format(target_device,
                                                                                                      target))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated ID Request messages...")

    def send_SRUP_Syndicated_Data(self, source_id, data_id, data, token=None):
        if type(source_id) is not str:
            raise ValueError

        # We can only send a syndicated data messages if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            if source_id[:2] == "0x":
                source_id = source_id[2:]
            SRUP_Syndicated_Data = pySRUPLib.SRUP_Syndicated_Data()
            if token is None:
                SRUP_Syndicated_Data.token = self._getToken()
            else:
                SRUP_Syndicated_Data.token = token

            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to our (local) C2 server
            # If we're a Syndicating C2 server – we can only send this to a syndication device...
            if isinstance(self, SyndicationDevice):
                target = self._server_id
            else:
                # ...we're a C2 server
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated Data Message – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_Data.sequence_id = s

            # We need to use the correct sender identity! C2 Servers only have one identity so that's easy.
            # But for syndicated devices we need to remember that we *can't* send data to the syndicated C2 – only
            # receive it *from* the syndicated C2 and send it back to our home C2...  So in either case we should use
            # the 'regular' device identity...
            SRUP_Syndicated_Data.sender_id = int(self._device_id, 16)

            SRUP_Syndicated_Data.source_id = int(source_id, 16)
            SRUP_Syndicated_Data.data_id = data_id

            # When we're sending data to a SRUP receiver we can determine the correct type function to used;
            # based on the type of the Python variable being sent…
            # Noting that there are actually far-fewer types in Python that we can use – than there are in C++...
            if type(data) is int:
                SRUP_Syndicated_Data.int32_data = data
            elif type(data) is float:
                # Remember Python only has double-precision floats...
                SRUP_Syndicated_Data.double_data = data
            elif type(data) is str:
                SRUP_Syndicated_Data.bytes_data = data

            # Similarly to the above note for sender identity - we'll always use our "local" key.
            key = self._local_private_key

            if not SRUP_Syndicated_Data.sign(key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_Data.serialize()
                if serial_data is not None:
                    # If we are a syndication device, we send to the server on *our* topic...
                    # ...but if we're a C2 server, we send on the *syndication device's* topic.
                    # Remember we never send syndication messages directly to end-user devices.
                    if isinstance(self, SyndicationDevice):
                        topic = "SRUP/{}".format(self._device_id)
                    else:
                        topic = "SRUP/{}".format(self._syndication_device_id)

                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending Syndicated Data Message to {} - (Source: {}: {}, {})".format(target,
                                                                                                       source_id,
                                                                                                       data_id,
                                                                                                       data))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated Data messages...")

    def send_SRUP_Syndicated_Device_List(self, device_sequence, device_id, token=None):
        # We can only send a syndicated device list messages if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            SRUP_Syndicated_Dev_List = pySRUPLib.SRUP_Syndicated_Device_List()
            if token is None:
                SRUP_Syndicated_Dev_List.token = self._getToken()
            else:
                SRUP_Syndicated_Dev_List.token = token

            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to a (syndicated) C2 server
            # If we're a Syndicating C2 server – we can only send this to a syndication device...
            if isinstance(self, SyndicationDevice):
                target = self._server_id
                print("Synd Dev List Target is {}".format(target))
            else:
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated Device List – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})

            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_Dev_List.device_id = device_id
            SRUP_Syndicated_Dev_List.device_sequence = device_sequence

            SRUP_Syndicated_Dev_List.sequence_id = s

            # This bit turns into a bit of a mind-warp...
            # For the sender – if we're a Syndication Device then we're sending to our home C2 Server (e.g. using our
            # primary identity); and if we're a C2 Server then we're sending to a syndication device – but
            # we (the server) only have *one* identity anyway... Either way this is self._device_id...
            SRUP_Syndicated_Dev_List.sender_id = int(self._device_id, 16)

            if not SRUP_Syndicated_Dev_List.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_Dev_List.serialize()
                if serial_data is not None:
                    # Unlike the previous part, here if we are a syndication device, we send to (our home) C2 server
                    # on *our* topic but if we're a C2 server, we send on the *syndication device's* topic.
                    # Remember we never send syndication messages directly to end-user devices.
                    if isinstance(self, SyndicationDevice):
                        topic = "SRUP/{}".format(self._device_id)
                    else:
                        topic = "SRUP/{}".format(target)
                    logging.info("Sending Syndicated Device List Message to {}".format(target))
                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated Device List messages...")

    def send_SRUP_Syndicated_Device_Count(self, count, token=None):
        # We can only send a syndicated device count if we're a server or a syndication device...
        if isinstance(self, Server) or isinstance(self, SyndicationDevice):
            SRUP_Syndicated_Dev_Count = pySRUPLib.SRUP_Syndicated_Device_Count()
            if token is None:
                SRUP_Syndicated_Dev_Count.token = self._getToken()
            else:
                SRUP_Syndicated_Dev_Count.token = token
            SRUP_Syndicated_Dev_Count.count = count
            # Who we're sending this to, depends on who we are...
            # If we're a Syndication Device - then we can only send this to a (syndicated) C2 server
            # If we're a Syndicating C2 server – we can only send this to a syndication device...
            if isinstance(self, SyndicationDevice):
                target = self._server_id
            else:
                if self._syndication_device_id is None:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Cannot send Syndicated Device Count – No Syndication Device ID is set.")
                    raise ValueError("No Syndication Device ID is set.")
                else:
                    target = self._syndication_device_id

            iTarget = int(target, 16)
            if iTarget not in self._seq_id_dict:
                self._seq_id_dict.update({iTarget: 0})
            self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
            s = self._seq_id_dict[iTarget]

            SRUP_Syndicated_Dev_Count.sequence_id = s
            SRUP_Syndicated_Dev_Count.sender_id = int(self._device_id, 16)
            if not SRUP_Syndicated_Dev_Count.sign(self._local_private_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Message Signing failed")
            else:
                serial_data = SRUP_Syndicated_Dev_Count.serialize()
                if serial_data is not None:
                    # If we are a syndication device, we send to the server on *our* topic...
                    # ...but if we're a C2 server, we send on the *syndication device's* topic.
                    # Remember we never send syndication messages directly to end-user devices.
                    if isinstance(self, SyndicationDevice):
                        topic = "SRUP/{}".format(self._device_id)
                    else:
                        topic = "SRUP/{}".format(self._syndication_device_id)

                    self._mqtt_client.publish(topic, serial_data, qos=1)
                    logging.info("Sending Syndicated Device ({}) Count to {}".format(count, target))
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices cannot send Syndicated Device Count messages...")

    def send_SRUP_Syndication_Request(self, id_value):
        # We can only send a syndication request if we're a syndication device...
        if isinstance(self, SyndicationDevice):
            self._send_Syndication_Request(id_value)
        else:
            # We can only send the Syndication Request if we're a syndication device...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only Syndication Devices can send Syndication Request messages...")

    def observation_valid(self, deviceID):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        status = SRUP_response_message.srup_response_status_observed_join_valid()
        self.send_SRUP_Response(self.server_id, status, self.__observer_token)

    def observation_invalid(self, deviceID):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        status = SRUP_response_message.srup_response_status_observed_join_invalid()
        self.send_SRUP_Response(self.server_id, status, self.__observer_token)

    def observation_fail(self, deviceID):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        status = SRUP_response_message.srup_response_status_observed_join_fail()
        self.send_SRUP_Response(self.server_id, status, self.__observer_token)


# Now that we have defined the base-class, we will derive two subclasses (one for devices),
# and one for servers...
# They are both very similar (as you'd expect) - but there are a few differences.
# Not least of which is the degree to which servers are not self-constructing - but rather need key exchange,
# and the establishment of their configuration files to be carried out manually, outside of the pySRUP constructs.
# Note: as of version 2.0 – we're renaming this sub-class to Device...
class Device (SRUP):
    def __init__(self, config_filename, base_registration_url, cert_chain=None, device_type=None):

        config = configparser.ConfigParser()
        settings = {}
        try:
            with open(config_filename) as f:
                config.read_file(f)

        except IOError as iox:
            # If errno == 2 (File Not Found) then do KeyEx...
            if iox.errno == 2:
                KeyEx(config_filename, base_registration_url, cert_chain, device_type=device_type)
                # This will create the config file – but just in case something is really badly broken
                # we'll try/except this too
                try:
                    with open(config_filename) as f:
                        config.read_file(f)
                except IOError:
                    # TODO: CUSTOM EXCEPTION
                    logging.error("The config file couldn't be created or opened after creation")
                    raise
            else:
                raise

        finally:
            config_to_load = {"Device": ["identity", "registration_url"], "SRUP": ["broker", "server_identity"],
                              "Keys": ["local_public", "local_private"],
                              "Access": ["key", "certificate", "ca_certificate"]}

            # We'll iterate through the config_to_load items: for each option we'll try to load it from the config, and
            # then we'll add it to the (flat) settings dictionary
            for section, options in config_to_load.items():
                for option in options:
                    try:
                        item = config.get(section, option)
                        settings.update({option: item})

                    # If anything fails we'll invoke a fatal error – either because the section in question is
                    # missing...
                    except configparser.NoSectionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Config file could not be loaded – section missing")
                        raise

                    # ... or the specific option is missing
                    except configparser.NoOptionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Config file could not be loaded – option missing")
                        raise
            try:
                seqids = config.get("SRUP", "Seq_IDs")
                raw_s_ids = ast.literal_eval(seqids)
                conv_s_ids = {}
                for d_id, s_id in raw_s_ids.items():
                    conv_s_ids[int(d_id, 16)] = s_id

                settings['Seq_IDs'] = conv_s_ids

                # Note the same fatal error if the section is missing
            # (although if we've got here that shouldn't be possible!)
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Config file could not be loaded")
                raise

            # Generate empty if not specified.
            except configparser.NoOptionError:
                seqids = "{}"
                settings['Seq_IDs'] = ast.literal_eval(seqids)

            # Now the same again for the remote keys
            # Noting that here (because we store the key as a Base64 encoded string for brevity – we need to unpack
            # it back into a Python string (convert from base64 encoding, and then from bytes to a string...
            try:
                remote_keys = config.get("Keys", "Remote_Keys")
                settings['remote_keys'] = ast.literal_eval(remote_keys)
                for d_id, d_key in settings['remote_keys'].items():
                    settings['remote_keys'][d_id] = base64.b64decode(d_key).decode()

            # Note the same fatal error if the section is missing
            # (although if we've got here that shouldn't be possible!)
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Config file could not be loaded")
                raise

            # Generate empty if not specified.
            except configparser.NoOptionError:
                remote_keys = "{}"
                settings['remote_keys'] = ast.literal_eval(remote_keys)

        if settings['registration_url'] != base_registration_url:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Registration URL mis-match...")

        super().__init__(broker=settings['broker'], device_id=settings['identity'],
                         local_private_key=settings['local_private'], local_public_key=settings['local_public'],
                         remote_public_keys=settings['remote_keys'], remote_device_types=None,
                         start_seq_id=settings['Seq_IDs'], registration_url=settings['registration_url'],
                         chain=cert_chain, server_id=settings['server_identity'],
                         ca_cert=settings['ca_certificate'], cert=settings['certificate'], key=settings['key'],
                         config_filename=config_filename)


class SyndicationDevice(Device):
    def __init__(self, config_filename, syndication_config_filename, base_registration_url, cert_chain=None,
                 device_type=None):
        # The constructor for the syndication device - is similar to the constructor for the regular device...
        # Although we can *load* some of the syndication specific fields from the config file – we can't specify them
        # as a part of the constructor...

        self._syndication_server_id = None
        self._syndication_device_id = None
        self._syndication_reg_url = None
        self._syndication_chain = None
        self._syndication_broker = None
        self.__syndication_mqtt_cert = None
        self._syndication_mqtt_key = None
        self._syndication_ca_cert = None
        self._syndication_public_key = None
        self._syndication_private_key = None
        self._syndication_active = False
        self.__syndication_join_pending = False
        self.__syndication_join_complete = False
        self.__syndication_mqtt_active = False
        self._on_syndication_device_init = None
        self.__syndication_id_value = ""
        self._config_file = config_filename
        self.__syndication_config_file = syndication_config_filename

        # This is a place-holder for the real client – which will create when we do init – or when we load an active
        # config from the file
        self._syndication_mqtt_client = None

        # We'll start by doing the superclass init (e.g. the regular device init).
        super().__init__(config_filename, base_registration_url, cert_chain=cert_chain, device_type=device_type)

        # Now we can just check the config file for syndication device specific config, and load it, if it's there...
        config = configparser.ConfigParser()
        settings = {}
        try:
            with open(syndication_config_filename) as f:
                config.read_file(f)

        except IOError as iox:
            logging.info("Syndication config file not found...")

    def __exit__(self, *args):
        if self.__syndication_mqtt_active:
            self._syndication_mqtt_client.disconnect()
            self._syndication_mqtt_client.loop_stop()
        super().__exit__(*args)

    @property
    def syndication_id_value(self):
        return self.__syndication_id_value

    @syndication_id_value.setter
    def syndication_id_value(self, id_value):
        # TODO: Validate id_value?...do we need to?
        self.__syndication_id_value = id_value

    def on_syndication_device_init(self, f):
        self._on_syndication_device_init = f

    def _on_syndication_connect(self, client, userdata, flags, rc):
        client.subscribe("SRUP/{}".format(self._syndication_device_id), qos=1)
        # And sleep for a moment - just to let Paho catch-up before we move on.
        time.sleep(1)

    def _on_syndication_init(self, mqtt_message):
        # Only syndication devices can handle syndication init messages...
        SRUP_Syndication_Init = pySRUPLib.SRUP_Syndication_Init()
        SRUP_Syndication_Init.deserialize(mqtt_message.payload)
        remote_key = self._get_key(SRUP_Syndication_Init.sender_id)
        logging.info("Syndication Init message received")
        if remote_key is None:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Syndication Init could not be validated - sender key not found.")
        else:
            if not SRUP_Syndication_Init.verify_keystring(remote_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Syndication Init did not verify using stored key.")
            else:
                # If we get to here – we have a valid syndication init message… So we now need to unpack it and
                # check to see if we have an existing syndication.conf file. If not, then we need to do
                # the "register" (KeyEx) and join process for the syndicated C2 network... as a part of this we also
                # need to set all of the "syndication" fields for later use.
                try:
                    f = open(self.__syndication_config_file)
                    f.close()

                except IOError:
                    logging.info("Starting Syndication KeyEx")
                    url = SRUP_Syndication_Init.url
                    logging.debug("Syndication URL {}".format(url))

                    id_value = SRUP_Syndication_Init.decrypt_keystring(self._local_private_key)
                    logging.debug("Syndication ID Value {}".format(id_value))

                    # KeyEx writes the config file – so we need to read that back; once we have it.
                    # We'll use a dedicated syndication config file; to prevent the need to rewrite the
                    # whole config file every time...
                    logging.debug("Initiating Syndication KeyEx with {}".format(url))
                    KeyEx(self.__syndication_config_file, url, self._syndication_chain, "Syndication Device",
                          syndication=True)

                logging.info("Loading Syndication Config")
                config = configparser.ConfigParser()
                settings = {}
                try:
                    with open(self.__syndication_config_file) as f:
                        config.read_file(f)

                except IOError as iox:
                    logging.error("The config file couldn't be created or opened after creation")

                finally:
                    config_to_load = {"Syndication": ["identity", "registration_url", "broker", "ca_cert",
                                                      "cert", "key", "server_identity", "syndication_public",
                                                      "syndication_private"]}
                    # Note we're not trying to load the chain here - # TODO: fix that

                    # We'll iterate through the config_to_load items: for each option we'll try to load it from
                    # the config
                    for section, options in config_to_load.items():
                        for option in options:
                            try:
                                item = config.get(section, option)
                                settings.update({option: item})

                            # If anything fails we'll just note it in log...
                            except configparser.NoSectionError:
                                logging.info("No Syndication section in config file")

                            except configparser.NoOptionError:
                                logging.info("Syndication Section error in config file ({})".format(option))

                if 'identity' in settings:
                    self._syndication_device_id = settings['identity']
                if 'registration_url' in settings:
                    self._syndication_reg_url = settings['registration_url']
                if 'chain' in settings:
                    self._syndication_chain = settings['chain']
                else:
                    self.__syndication_chain = None
                if 'broker' in settings:
                    self._syndication_broker = settings['broker']
                if 'ca_cert' in settings:
                    self._syndication_ca_cert = settings['ca_cert']
                if 'cert' in settings:
                    self.__syndication_mqtt_cert = settings['cert']
                if 'key' in settings:
                    self._syndication_mqtt_key = settings['key']
                if 'syndication_public' in settings:
                    self._syndication_public_key = settings['syndication_public']
                if 'syndication_private' in settings:
                    self._syndication_private_key = settings['syndication_private']
                if 'server_identity' in settings:
                    self._syndication_server_id = settings['server_identity']

                self._syndication_mqtt_client = mqtt.Client(client_id="SRUP Client: {}".
                                                            format(self._syndication_device_id))

                self._syndication_mqtt_client.tls_set(ca_certs=self._syndication_ca_cert,
                                                      certfile=self.__syndication_mqtt_cert,
                                                      keyfile=self._syndication_mqtt_key)

                self._syndication_mqtt_client.on_message = self._on_mqtt_message
                self._syndication_mqtt_client.on_connect = self._on_syndication_connect

                # Provide an opportunity to call user code to (e.g.) display a message...
                if self._on_syndication_device_init is not None:
                    self._on_syndication_device_init()

                logging.info("Syndication Device ID {}".format(self._syndication_device_id))
                logging.info("Connecting to MQTT Broker {}".format(self._syndication_broker))
                try:
                    if self._syndication_broker[:4].lower() == 'mqtt':
                        self._syndication_broker = self._syndication_broker[7:].lower()

                    self._syndication_mqtt_client.connect(self._syndication_broker, 8883, 60)
                    self._syndication_mqtt_client.loop_start()
                except Exception as e:
                    logging.error(e)

                self.__syndication_mqtt_active = True

                # We've registered – so next we need to join...
                # We'll use a human join (though this could be swapped for an observed – aka machine-moderated) join
                # in the future... We use a custom sending function, override the base class handler for join responses
                time.sleep(1)
                logging.info("Starting Syndication Join to {}".format(self._syndication_server_id))
                self._syndication_join()

    def _send_Syndication_Request(self, id_value):
        SRUP_Syndication_Request = pySRUPLib.SRUP_Syndication_Request()
        SRUP_Syndication_Request.token = self._getToken()
        if self._syndication_server_id is None:
            # TODO: THROW A CUSTOM EXCEPTION
            # We shouldn't really ever get here – as the only reason we'd be sending this is as a response to a
            # syndication init message – and in handling that: we should have set all of the parameters already...
            # But just in case!
            logging.error("Cannot send Syndicated Device Count – No Syndicated Server ID is set.")
            raise ValueError("No Syndicated Server ID is set.")
        else:
            target = self._syndication_server_id

        iTarget = int(target, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        SRUP_Syndication_Request.sequence_id = s
        SRUP_Syndication_Request.sender_id = int(self._syndication_device_id, 16)

        if self._get_key(target) is None:
            self._add_key_from_keyservice(target, syndication=True)

        key = self._get_key(target)
        SRUP_Syndication_Request.encrypt_keystring(id_value, key)

        # Now we're all done – so we can sign it.
        if not SRUP_Syndication_Request.sign(self._syndication_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_Syndication_Request.serialize()
            if serial_data is not None:
                topic = "SRUP/{}".format(self._syndication_device_id)
                # Remembering to send on the syndication MQTT client / interface...
                logging.info("Sending Syndication Request message to {}".format(target))
                self._syndication_mqtt_client.publish(topic, serial_data, qos=1)
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")

    def _syndication_join(self):
        # The process we need to follow here is to:
        #   * Send a human join
        #   * Set a flag
        #   * Wait for join_success response message & return true
        #   * Or return false - if we fail.
        if self.__send_syndication_human_join():
            self.__syndication_join_pending = True
            while self.__syndication_join_pending:
                time.sleep(1)
            if self.__syndication_join_complete:
                # Lastly, we need to send our own syndication_request message to the syndicated C2 server to
                # actually start the syndication
                # However – we need to briefly pause for any other automatically sent messages to be processed
                # otherwise we risk out-of-sequence processing. e.g. After a join there will typically be an
                # ID Request, so we should sleep *this thread* to wait...
                time.sleep(2)
                logging.info("Sending Syndication Request – ID Value {}".format(self.__syndication_id_value))
                self.send_SRUP_Syndication_Request(self.__syndication_id_value)
                self._syndication_active = True
                time.sleep(1)
            else:
                logging.error("Syndication Join Failure")
                # TODO: Something more useful...
        else:
            logging.info("Human Join Failed")
            # TODO: Something ...

    def __send_syndication_human_join(self):
        SRUP_Human_Join_Request = pySRUPLib.SRUP_Human_Join_Request()
        SRUP_Human_Join_Request.token = self._getToken()
        iTarget = int(self._syndication_server_id, 16)

        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        # We must also get the server's key – if we don't already have it...
        if iTarget not in self._keystore:
            self._add_key_from_keyservice(iTarget, syndication=True)

        SRUP_Human_Join_Request.sequence_id = s
        SRUP_Human_Join_Request.sender_id = int(self._syndication_device_id, 16)
        if not SRUP_Human_Join_Request.sign(self._syndication_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_Human_Join_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/servers/{}/{}".format(self._syndication_server_id, self._syndication_device_id)
                self._syndication_mqtt_client.publish(topic, serial_data, qos=1)
                logging.info("Sending HUMAN JOIN Request to {}".format(self._syndication_server_id))
                time.sleep(1)
                return True
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")
                return False

    def _on_response(self, SRUP_response_message):
        # We're only interested in JOIN responses – and only then, if we have a syndication join pending...
        # For anything else – just pass back up to the parent class to handle.
        if self.__syndication_join_pending:
            if SRUP_response_message.status == SRUP_response_message.srup_response_status_join_success():
                self.__syndication_join_complete = True
                self.__syndication_join_pending = False
                logging.info("Syndication Device Join Complete")
                super(SyndicationDevice, self)._on_response(SRUP_response_message)
            elif SRUP_response_message.status == SRUP_response_message.srup_response_status_join_fail():
                logging.error("Syndication Device Join Fail")
                super(SyndicationDevice, self)._on_response(SRUP_response_message)
            else:
                logging.info("Message Status {}".format(hex(SRUP_response_message.status)))
                super(SyndicationDevice, self)._on_response(SRUP_response_message)
        else:
            super(SyndicationDevice, self)._on_response(SRUP_response_message)


# There are a few differences between devices and servers...
# The most significant one is that we do not do key exchange for servers; rather we require this to be done outside
# of the pySRUP construct. This is to ensure that only legitimate server's can be issued a server certificate.
# There would be a significant security vulnerability if this protection wasn't in place.
class Server (SRUP):
    def __init__(self, config_filename):
        # We'll start with some additional class member variables...
        # Note that many of these are used by the base class methods!
        self._syndication_device_id = None
        self._server_token_file = None
        self._syndication_active = False
        self._on_syndication_request = None
        self._on_syndicated_device_list = None
        self.__device_types = {}
        self._pending_joins = {}

        # We'll create an empty dictionary for "syndicating" devices – which let's us check if we have received all
        # of them - and which (if any) we might be missing…
        # Actually doing this is something for a future revision of the protocol & library – since at present we don't
        # have a mechanism to report than any are missing, and/or to request that the syndicated server resends them.
        self._syndicating_devices = {}
        self._expected_syndicating_devices_count = None

        # Lastly create an empty list of "joined" devices...
        self._controlled_devices = []

        # Now we'll go into parsing the config file.
        config = configparser.ConfigParser()
        settings = {}
        try:
            with open(config_filename) as f:
                config.read_file(f)

        except IOError as iox:
            logging.error("The specified server config file ({}) couldn't be opened".format(config_filename))
            raise

        else:
            config_to_load = {"Server": ["identity", "registration_url", "server_token_file"],
                              "SRUP": ["broker"],
                              "Keys": ["local_public", "local_private"],
                              "Devices": ["device_types"],
                              "Access": ["key", "certificate", "ca_certificate"]}

            # We'll iterate through the config_to_load items: for each option we'll try to load it from the config, and
            # then we'll add it to the (flat) settings dictionary
            for section, options in config_to_load.items():
                for option in options:
                    try:
                        item = config.get(section, option)
                        settings.update({option: item})

                    # If anything fails we'll invoke a fatal error – either because the section in question is
                    # missing...
                    except configparser.NoSectionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Config file could not be loaded")
                        raise

                    # ... or the specific option is missing
                    except configparser.NoOptionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Config file could not be loaded")
                        raise

            # Now some special cases – loading dictionaries for Seq_IDs, remote keys & device types...
            # Noting that either of these could be "blank" (or not included).
            # First the sequence IDs...
            try:
                seqids = config.get("SRUP", "Seq_IDs")
                raw_s_ids = ast.literal_eval(seqids)
                conv_s_ids = {}
                for d_id, s_id in raw_s_ids.items():
                    conv_s_ids[int(d_id, 16)] = s_id

                settings['Seq_IDs'] = conv_s_ids

            # Note the same fatal error if the section is missing
            # (although if we've got here that shouldn't be possible!)
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Config file could not be loaded")
                raise

            # Generate empty if not specified.
            except configparser.NoOptionError:
                seqids = "{}"
                settings['Seq_IDs'] = ast.literal_eval(seqids)

            # Now the same again for the remote keys
            # As for the client, we must unpack the base64 encoded key(s) back into Python string(s)
            try:
                remote_keys = config.get("Keys", "Remote_Keys")
                settings['remote_keys'] = ast.literal_eval(remote_keys)
                for d_id, d_key in settings['remote_keys'].items():
                    settings['remote_keys'][d_id] = base64.b64decode(d_key).decode()

            # Note the same fatal error if the section is missing
            # (although if we've got here that shouldn't be possible!)
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Config file could not be loaded")
                raise

            # Generate empty if not specified.
            except configparser.NoOptionError:
                remote_keys = "{}"
                settings['remote_keys'] = ast.literal_eval(remote_keys)

            # Next look for a CA chain...
            try:
                chain = config.get("Server", "Chain")
                settings['chain'] = chain

            except configparser.NoOptionError:
                # If the option is not present – we'll load the value as None...
                settings['chain'] = None

            # Lastly we do the same process for the device types
            try:
                device_types = config.get("Devices", "Device_Types")
                settings['device_types'] = ast.literal_eval(device_types)

            # If the section is missing; raise an error...
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Config file could not be loaded")
                raise

            # But generate the empty dictionary if device types option is not specified.
            except configparser.NoOptionError:
                device_types = "{}"
                settings['device_types'] = ast.literal_eval(device_types)

        # Lastly, before we call the constructor, we should check to see if our KeyEx backend already has
        # our public key ... and if not, then we need to register ourselves with the KeyEx service.
        # We have a helper function in KeyEx client to do all of this for us... So we'll just call that here.
        if KeyEx_C2(settings['registration_url'], settings['chain'], settings['identity'],
                    settings['local_public'], settings['server_token_file']):
            time.sleep(1)
            super().__init__(settings['broker'], settings['identity'], local_private_key=settings['local_private'],
                             local_public_key=settings['local_public'], remote_public_keys=settings['remote_keys'],
                             chain=settings['chain'], remote_device_types=settings['device_types'],
                             start_seq_id=settings['Seq_IDs'], registration_url=settings['registration_url'],
                             server_id=None, ca_cert=settings['ca_certificate'], cert=settings['certificate'],
                             key=settings['key'], config_filename=config_filename)

            self._server_token_file = settings['server_token_file']
        else:
            # KeyEx_C2 failed...
            # TODO: THROW A CUSTOM EXCEPTION?
            logging.error("KeyEx C2 Failed - cannot Start C2 Server")

    @property
    def device_types(self):
        return self._deviceTypes

    @property
    def syndicating_devices(self):
        return self._syndicating_devices

    @property
    def syndication_active(self):
        return self._syndication_active

    @property
    def syndication_device_id(self):
        return self._syndication_device_id

    @syndication_device_id.setter
    def syndication_device_id(self, dev_id):
        self._syndication_device_id = dev_id

    def accept_join(self, deviceID, ID_req=False):
        if deviceID in self._pending_joins:
            # To accept the join; the next step is to subscribe to the topic corresponding to the device;
            # and send a response message on that topic.
            self._mqtt_client.subscribe("SRUP/{}/#".format(deviceID), qos=1)
            SRUP_response_message = pySRUPLib.SRUP_Response()
            status = SRUP_response_message.srup_response_status_join_success()

            # Lastly we add the new device to the controlled_devices list.
            self._controlled_devices.append("{}".format(deviceID))

            self.send_SRUP_Response(deviceID, status, self._pending_joins[deviceID])
            # Now we've done with the token – we should delete the dictionary entry...
            del self._pending_joins[deviceID]

            if ID_req:
                self.send_SRUP_ID_Request(deviceID)

        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device ID {:x} not found in pending joins.".format(deviceID))

    def refuse_join(self, deviceID):
        if deviceID in self._pending_joins:
            # To refuse the join we just need to send a response message.
            # (We'll use the device's topic – but *we* don't need to be subscribed to send it)...
            SRUP_response_message = pySRUPLib.SRUP_Response()
            status = SRUP_response_message.srup_response_status_join_refused()
            self.send_SRUP_Response(deviceID, status, self._pending_joins[deviceID])

            # Now we've done with the token – we should delete the dictionary entry...
            # The new join (if we get one) will use a new token.
            del self._pending_joins[deviceID]

        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device ID {:x} not found in pending joins.".format(deviceID))

    def fail_join(self, deviceID):
        if deviceID in self._pending_joins:
            # To reject the join we just need to send a 'join fail' response message.
            # (We'll use the device's topic – but *we* don't need to be subscribed to send it)...
            SRUP_response_message = pySRUPLib.SRUP_Response()
            status = SRUP_response_message.srup_response_status_join_fail()
            self.send_SRUP_Response(deviceID, status, self._pending_joins[deviceID])

            # Now we've done with the token – we should delete the dictionary entry...
            # The new join (if we get one) will use a new token.
            del self._pending_joins[deviceID]
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device ID {:x} not found in pending joins.".format(deviceID))

    def send_SRUP_Syndicated_Terminate_message(self, token=None):
        super(Server, self).send_SRUP_Syndicated_Terminate_message(token)
        self._syndication_active = False
        self._syndication_device_id = None

    def get_devices(self):
        return self._controlled_devices

    def on_syndication_request(self, f):
        self._on_syndication_request = f

    def on_syndicated_device_list(self, f):
        self._on_syndicated_device_list = f

    def send_SRUP_Syndication_Init(self, url, id_value, syndication_device_id):
        # TODO: Add ability to specify a web certificate chain for the syndication URL...
        # We can only send a syndicated init if we're a server

        SRUP_Syndication_Init = pySRUPLib.SRUP_Syndication_Init()
        SRUP_Syndication_Init.token = self._getToken()
        self._syndication_device_id = syndication_device_id
        target = syndication_device_id

        iTarget = int(target, 16)
        if iTarget not in self._seq_id_dict:
            self._seq_id_dict.update({iTarget: 0})
        self._seq_id_dict.update({iTarget: self._seq_id_dict[iTarget] + 1})
        s = self._seq_id_dict[iTarget]

        if self._get_key(syndication_device_id) is None:
            self._add_key_from_keyservice(syndication_device_id)

        key = self._get_key(syndication_device_id)

        SRUP_Syndication_Init.sequence_id = s
        SRUP_Syndication_Init.sender_id = int(self._device_id, 16)
        SRUP_Syndication_Init.url = url
        SRUP_Syndication_Init.encrypt_keystring(id_value, key)

        # Now we're all done – so we can sign it.
        if not SRUP_Syndication_Init.sign(self._local_private_key):
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message Signing failed")
        else:
            serial_data = SRUP_Syndication_Init.serialize()
            if serial_data is not None:
                topic = "SRUP/{}".format(self._syndication_device_id)
                self._mqtt_client.publish(topic, serial_data, qos=1)
                logging.info("Sending Syndication Init message to {}".format(target))
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")
