import sys
sys.path.append('../../')

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
import sqlite3

from KeyEx_Client import KeyEx

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
SRUP_DERESISTER_COMMNAND_MESSAGE_TYPE = pySRUPLib.__deregister_command_message_type()
SRUP_OBSERVED_JOIN_REQUEST_MESSAGE_TYPE = pySRUPLib.__observed_join_request_message_type()
SRUP_OBSERVED_JOIN_RESPONSE_MESSAGE_TYPE = pySRUPLib.__observed_join_response_message_type()
SRUP_OBSERVATION_REQUEST_MESSAGE_TYPE = pySRUPLib.__observation_request_message_type()

# As of the current version of the pySRUP code (changed - Feb 2019) we'll exclusively use the key-string
# rather than key file for non-local keys...
# The underpinning C++ library will continue to support both – as will the direct pySRUPLib port to Python.
# (Not least so that we can use key files for the local keys...)
# For this to work, we need to add the key to the in-memory data structure in the event of the
# JOIN, so that for any other message handler, we can assume that (for any joined device) the
# key will (should) be in the keystore.


class SRUP:

    __keyExRoute = '/KeyEx/register/get_key/'
    __deviceTypeRoute = '/KeyEx/register/get_type/'

    def __init__(self, broker, device_id, local_private_key, local_public_key, remote_public_keys, remote_device_types,
                 start_seq_id, registration_url, server_id, ca_cert, cert, key, config_filename, server=False):
        self.__isServer = server
        self.__seq_id = start_seq_id
        self.__device_id = device_id
        # Strip the mqtt:// part from the broker URL
        if broker[:7] == 'mqtt://':
            broker = broker[7:]
        self.__broker = broker
        self.__local_private_key = local_private_key
        self.__local_public_key = local_public_key

        # We'll use keystore - for any active non–local keys...
        # e.g. Any devices connected to this server, or any servers that this device is connected to.
        if remote_public_keys is None:
            self.__keystore = {}
        else:
            self.__keystore = remote_public_keys

        self.__pending_joins = {}

        # We use a similar data structure for the device type...
        # TODO: Consider merging these two into a more complex data dictionary or database?
        if remote_device_types is None:
            self.__deviceTypes = {}
        else:
            self.__deviceTypes = remote_device_types

        self.__ca_cert = ca_cert
        self.__mqtt_cert = cert
        self.__mqtt_key = key
        self.__reg_url = registration_url
        self.__server_id = server_id

        self.__open_update_tokens = {}
        self.__on_action = None
        self.__on_data = None
        self.__on_update = None
        self.__on_update_success = None
        self.__fetch_auth = None
        self.__fetch_filename = None
        self.__on_id_request = None
        self.__on_terminate = None
        self.__on_join_command = None
        self.__on_join_request = None
        self.__on_join_refused = None
        self.__on_join_failed = None
        self.__on_join_succeed = None
        self.__on_resign_request = None
        self.__on_deregister_request = None
        self.__on_degregister_command = None
        self.__on_human_join_request = None
        self.__on_human_join_response = None
        self.__on_observed_join_request = None
        self.__on_observed_join_response = None
        self.__on_observation_request = None
        self.__on_observed_join_succeed = None
        self.__on_observed_join_invalid = None
        self.__on_observed_join_fail = None

        self.__config_filename = config_filename
        self.__mqtt_client = mqtt.Client(client_id="SRUP Client: {}".format(device_id))
        self.__mqtt_client.on_connect = self.__on_connect
        self.__mqtt_client.on_message = self.__on_mqtt_message
        self.__mqtt_client.tls_set(ca_certs=self.__ca_cert, certfile=self.__mqtt_cert, keyfile=self.__mqtt_key)
        self.__pySRUP_Version = lambda: "{}.{}".format(self.__pySRUP_Version_major, self.__pySRUP_Version_minor)
        self.__pySRUP_Version_major = lambda: 1
        self.__pySRUP_Version_minor = lambda: 1

        self.__observer_token = None

        # Lastly create an empty list of "joined" devices...
        # This will always remain blank for devices...
        self.__controlled_devices = []

    def __enter__(self):
        self.__mqtt_client.connect(self.__broker, 8883, 60)
        self.__mqtt_client.loop_start()

    def __exit__(self, *args):
        self.__mqtt_client.disconnect()
        self.__mqtt_client.loop_stop()

    # We'll expose a couple of internal member variables as properties...
    @property
    def server_id(self):
        return self.__server_id

    @server_id.setter
    def server_id(self, sid):
        # TODO: Validate sid...
        self.__server_id = sid

    @property
    def id(self):
        return self.__device_id

    @property
    def device_keys(self):
        if self.__isServer:
            return list(self.__keystore)
        else:
            return []

    @property
    def device_types(self):
        if self.__isServer:
            return self.__deviceTypes
        else:
            return {}

    def __add_key_from_keyservice(self, sender):
        # Assuming we don't already have the key in memory; then we must fetch the key-string from the
        # keyserver (which will send it as a base64 encoded string), decode it, and then store it in the
        # dictionary - using the device ID as the key.
        hex_sender = self.__convert_sender_format(sender)
        r = requests.get(self.__reg_url + self.__keyExRoute + hex_sender)
        if r.status_code == 200:
            remote_key = base64.b64decode(r.text).decode()
            self.__keystore[hex_sender] = remote_key
            return True
        else:
            return False

    def __get_device_type(self, sender):
        hex_sender = self.__convert_sender_format(sender)
        r = requests.get(self.__reg_url + self.__deviceTypeRoute + hex_sender)
        if r.status_code == 200:
            self.__deviceTypes[hex_sender] = r.text
            return True
        else:
            return False

    def __convert_sender_format(self, sender):
        # TODO: We might also need to do something here to ensure that we parse the "pure" hex to the typical UUID
        #       format e.g. in the format 8-4-4-4-12 such as 123e4567-e89b-12d3-a456-426655440000
        #       At least we might when we start to use newly issued IDs from the Key Service...
        if isinstance(sender, int):
            return "{:02x}".format(sender)
        elif isinstance(sender, str):
            return sender
        else:
            return None

    def __get_key(self, sender):
        hex_sender = self.__convert_sender_format(sender)
        if hex_sender in self.__keystore:
            return self.__keystore[hex_sender]
        else:
            return None

    def __get_type(self, sender):
        hex_sender = self.__convert_sender_format(sender)
        if hex_sender in self.__deviceTypes:
            return self.__deviceTypes[hex_sender]
        else:
            return None

    def __on_connect(self, client, userdata, flags, rc):
        # If we're a server we need to subscribe to our "server" topic - to await join requests...
        # Whereas if we're not, we need to subscribe to our "device-level" topic.
        # Although servers (probably – depending on the specific broker-side implementation) can subscribe to the
        # root SRUP topic - they shouldn't do that, to avoid receiving messages intended for other servers
        # (which on a real system could be numerous).
        if self.__isServer:
            client.subscribe("SRUP/servers/{}/#".format(self.__device_id))
        else:
            client.subscribe("SRUP/{}".format(self.__device_id))
        # And sleep for a moment - just to let Paho catch-up before we move on.
        time.sleep(0.5)

    def __on_mqtt_message(self, client, userdata, msg):
        # First check if the message is even for us...
        # Remembering that server's are wild...
        topic = None
        ch_topic = msg.topic
        if ch_topic[0:5] == 'SRUP/':
            topic = ch_topic[5:]

        # First check if the message is for us (or if we're a server read it anyway)
        if topic == self.__device_id or self.__isServer:
            SRUP_generic_message = pySRUPLib.SRUP_Generic()

            # if de-serializes then it's probably a SRUP message...
            if SRUP_generic_message.deserialize(msg.payload):

                # Did we send it? If so, ignore it...
                if SRUP_generic_message.sender_id != int(self.__device_id, 16):

                    # Check to see if we've had a message from this sender before (creating a counter if we haven't)
                    if SRUP_generic_message.sender_id not in self.__seq_id:
                        self.__seq_id.update({SRUP_generic_message.sender_id: 0})

                    # Get current sequence ID for this sender...
                    s = self.__seq_id[SRUP_generic_message.sender_id]

                    # Check to see the sequence ID of the message is greater than the last received message
                    # to avoid replay attack...
                    if SRUP_generic_message.sequence_id > s:
                        # Update the "last received" sequence ID for this sender...
                        # Get the message type of the generic message - and compare with valid message types...

                        self.__seq_id[SRUP_generic_message.sender_id] = SRUP_generic_message.sequence_id
                        msg_type = SRUP_generic_message.msg_type

                        if msg_type == SRUP_ACTION_MESSAGE_TYPE:
                            self.__handle_action_message(msg)
                        elif msg_type == SRUP_DATA_MESSAGE_TYPE:
                            self.__handle_data_message(msg)
                        elif msg_type == SRUP_INITIATE_MESSAGE_TYPE:
                            self.__handle_init_message(msg)
                        elif msg_type == SRUP_RESPONSE_MESSAGE_TYPE:
                            self.__handle_response_message(msg)
                        elif msg_type == SRUP_ACTIVATE_MESSAGE_TYPE:
                            self.__handle_activate_message(msg)
                        elif msg_type == SRUP_ID_REQUEST_MESSAGE_TYPE:
                            self.__handle_id_req_message(msg)
                        elif msg_type == SRUP_JOIN_REQUEST_MESSAGE_TYPE:
                            self.__handle_join_request_message(msg)
                        elif msg_type == SRUP_TERMINATE_COMMAND_MESSAGE_TYPE:
                            self.__handle_terminate_message(msg)
                        elif msg_type == SRUP_JOIN_COMMAND_MESSAGE_TYPE:
                            self.__handle_join_command_message(msg)
                        elif msg_type == SRUP_RESIGN_REQUEST_MESSAGE_TYPE:
                            self.__handle_resign_request_message(msg)
                        elif msg_type == SRUP_DEREGISTER_REQUEST_MESSAGE_TYPE:
                            self.__handle_deregister_request_message(msg)
                        elif msg_type == SRUP_DERESISTER_COMMNAND_MESSAGE_TYPE:
                            self.__handle_deregister_command_message(msg)
                        elif msg_type == SRUP_HUMAN_JOIN_REQUEST_MESSAGE_TYPE:
                            self.__handle_human_join_request_message(msg)
                        elif msg_type == SRUP_HUMAN_JOIN_RESPONSE_MESSAGE_TYPE:
                            self.__handle_human_join_response_message(msg)
                        elif msg_type == SRUP_OBSERVATION_REQUEST_MESSAGE_TYPE:
                            self.__handle_observation_request_message(msg)
                        elif msg_type == SRUP_OBSERVED_JOIN_REQUEST_MESSAGE_TYPE:
                            self.__handle_observed_join_request_message(msg)
                        elif msg_type == SRUP_OBSERVED_JOIN_RESPONSE_MESSAGE_TYPE:
                            self.__handle_observed_join_response_message(msg)
                        else:
                            # We have received a message type that we can't handle...
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Invalid message type or format. (Message type = {}, SeqID = {})".
                                            format(format(SRUP_generic_message.msg_type,'#04x'),
                                                          SRUP_generic_message.sequence_id))

                    else:
                        # We have an invalid sequence ID...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Sequence ID 0x{:02X} is invalid".format(SRUP_generic_message.sequence_id))
                        logging.debug("Sender: {}".format(hex(SRUP_generic_message.sender_id)))
                else:
                    # This is a message that we sent – so ignore it...
                    pass

            else:
                # Message is corrupted - or otherwise didn't deserialize...
                pass
                logging.warning("Message did not deserialize...")
                # TODO: Not a SRUP Message ...
        else:
            # Not a message meant for us – so skip it...
            pass
            logging.info("Message not for this receiver")

    def __handle_action_message(self, mqtt_message):
        SRUP_action_message = pySRUPLib.SRUP_Action()
        SRUP_action_message.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_action_message.sender_id)

        if remote_key is not None:
                if SRUP_action_message.verify_keystring(remote_key):
                    if "{:x}".format(SRUP_action_message.sender_id) == self.__server_id or self.__isServer:
                        self.__on_action(SRUP_action_message)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def __handle_data_message(self, mqtt_message):
        SRUP_data_message = pySRUPLib.SRUP_Data()
        SRUP_data_message.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_data_message.sender_id)
        if remote_key is not None:
            if SRUP_data_message.verify_keystring(remote_key):
                if "{:x}".format(SRUP_data_message.sender_id) == self.__server_id or self.__isServer:
                    self.__on_data(SRUP_data_message)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def __handle_init_message(self, mqtt_message):
        # Devices can't send init messages – so skip this if we're a server...
        if not self.__isServer:
            SRUP_initiate_message = pySRUPLib.SRUP_Initiate()
            SRUP_initiate_message.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_initiate_message.sender_id)
            if remote_key is not None:
                if SRUP_initiate_message.verify_keystring(remote_key):
                    if "{:x}".format(SRUP_initiate_message.sender_id) == self.__server_id or self.__isServer:
                        self.__on_initiate(SRUP_initiate_message)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")

    def __handle_response_message(self, mqtt_message):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        SRUP_response_message.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_response_message.sender_id)
        if remote_key is not None:
            if SRUP_response_message.verify_keystring(remote_key):
                if "{:x}".format(SRUP_response_message.sender_id) == self.__server_id or self.__isServer:
                            self.__on_response(SRUP_response_message)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def __handle_activate_message(self, mqtt_message):
        # Devices can't send activate messages either – so again, we'll skip if we're a server.
        if not self.__isServer:
            SRUP_activate_message = pySRUPLib.SRUP_Activate()
            SRUP_activate_message.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_activate_message.sender_id)
            if remote_key is not None:
                if SRUP_activate_message.verify_keystring(remote_key):
                    if "{:x}".format(SRUP_activate_message.sender_id) == self.__server_id or self.__isServer:
                        self.__on_activate(SRUP_activate_message)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")

    def __handle_id_req_message(self, mqtt_message):
        SRUP_id_request_message = pySRUPLib.SRUP_ID_Request()
        SRUP_id_request_message.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_id_request_message.sender_id)
        if remote_key is not None:
            if not SRUP_id_request_message.verify_keystring(remote_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key")
            else:
                if "{:x}".format(SRUP_id_request_message.sender_id) == self.__server_id or self.__isServer:
                    # If we've received an ID request message - we should call the custom handler
                    # (if we have one), or just return a default message, if we don't...
                    logging.info("ID Request Received...")
                    if self.__on_id_request is None:
                        resp = "pySRUP version " + str(self.__pySRUP_Version())
                    else:
                        resp = self.__on_id_request()

                    tid = SRUP_id_request_message.sender_id
                    self.send_SRUP_Data(target_id=hex(tid), data_id="IDENTIFICATION_RESPONSE", data=resp)
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Sender not found in keystore.")

    def __handle_join_request_message(self, mqtt_message):
        # Devices shouldn't receive join requests - so skip if not server...
        if self.__isServer:
            # Check the topic...to see if this is for us...
            if not bool(re.search('\ASRUP/servers/' + re.escape(self.__device_id) + '/\w+\Z', mqtt_message.topic)):
                # TODO: THROW A CUSTOM EXCEPTION?
                # We shouldn't be subscribed to another server's "JOIN" topic – so something went a bit wrong...
                logging.debug(mqtt_message.topic)
                logging.info("Message not for this server {}".format(re.findall('\ASRUP/servers/(\w+)/\w+\Z',
                                                                                mqtt_message.topic)))
            else:
                SRUP_join_request = pySRUPLib.SRUP_Join_Request()
                SRUP_join_request.deserialize(mqtt_message.payload)

                remote_key = self.__get_key(SRUP_join_request.sender_id)
                if remote_key is None:
                    # We don't already have the key – so fetch it...
                    # If we get one, proceed – if not then log the error
                    if not self.__add_key_from_keyservice(SRUP_join_request.sender_id):
                        # We can't find the key at the keyserver...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Sender ({}) could not be found at KeyEx lookup service".
                                      format(self.__convert_sender_format(SRUP_join_request.sender_id)))
                        return
                    else:
                        remote_key = self.__get_key(SRUP_join_request.sender_id)

                # Next we need to check to see if we have the device type - as we may need this later on...
                if self.__get_type(SRUP_join_request.sender_id) is None:
                    self.__get_device_type(SRUP_join_request.sender_id)

                if not SRUP_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    joining_device = SRUP_join_request.sender_id
                    hex_joining_device = hex(joining_device).lstrip('0x')
                    logging.info("JOIN Request received from {}".format(hex_joining_device))

                    # Add the device ID & token to pending joins...
                    self.__pending_joins[hex_joining_device] = SRUP_join_request.token

                    # We'll now give the "user program" the chance to accept or reject the join request...
                    # To do this, we will call the registered callback function if there is one.
                    # We'll assume that if the user hasn't registered on – then a simple join request will always be
                    # (automatically) accepted – and responded to.

                    if self.__on_join_request is not None:
                        # We'll call the user's function (providing them the device ID of the device).
                        # It'll then be up to the user-code to call the .join_accept(devID) method to accept the join.
                        # They can do this using device type – which can be retrieved by using the .device_types method
                        self.__on_join_request(hex_joining_device)
                    else:
                        self.accept_join(hex_joining_device)

    def __handle_human_join_request_message(self, mqtt_message):
        # Devices shouldn't receive join requests - so skip if not server...
        if self.__isServer:
            # Check the topic...to see if this is for us...
            if not bool(re.search('\ASRUP/servers/' + re.escape(self.__device_id) + '/\w+\Z', mqtt_message.topic)):
                # TODO: THROW A CUSTOM EXCEPTION?
                # We shouldn't be subscribed to another server's "JOIN" topic – so something went a bit wrong...
                logging.debug(mqtt_message.topic)
                logging.info("Message not for this server {}".format(re.findall('\ASRUP/servers/(\w+)/\w+\Z',
                                                                                mqtt_message.topic)))
            else:
                SRUP_human_join_request = pySRUPLib.SRUP_Human_Join_Request()
                SRUP_human_join_request.deserialize(mqtt_message.payload)

                remote_key = self.__get_key(SRUP_human_join_request.sender_id)
                if remote_key is None:
                    # We don't already have the key – so fetch it...
                    # If we get one, proceed – if not then log the error
                    if not self.__add_key_from_keyservice(SRUP_human_join_request.sender_id):
                        # We can't find the key at the keyserver...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Sender ({}) could not be found at KeyEx lookup service".
                                      format(self.__convert_sender_format(SRUP_human_join_request.sender_id)))
                        return
                    else:
                        remote_key = self.__get_key(SRUP_human_join_request.sender_id)

                # Next we need to check to see if we have the device type - as we may need this later on...
                if self.__get_type(SRUP_human_join_request.sender_id) is None:
                    self.__get_device_type(SRUP_human_join_request.sender_id)

                if not SRUP_human_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    joining_device = SRUP_human_join_request.sender_id
                    hex_joining_device = hex(joining_device).lstrip('0x')
                    logging.info("HUMAN JOIN Request received from {}".format(hex_joining_device))

                    # Add the device ID & token to pending joins...
                    self.__pending_joins[hex_joining_device] = SRUP_human_join_request.token

                    # We'll now give the "user program" the chance to accept or reject the join request...
                    # To do this, we will call the registered callback function if there is one.
                    # We'll assume that if the user hasn't registered on – then a simple join request will always be
                    # (automatically) accepted – and responded to.

                    if self.__on_human_join_request is not None:
                        # We'll call the user's function (providing them the device ID of the device).
                        # It'll then be up to the user-code to call the .join_accept(devID) method to accept the join.
                        # They can do this using device type – which can be retrieved by using the .device_types method
                        self.__on_human_join_request(hex_joining_device)
                    else:
                        # Send srup_response_status_join_fail – since we have no handler for this kind of message.
                        self.fail_join(hex_joining_device)
                        logging.warning("Human Moderated Join Message Rejected – __on_human_join_request "
                                        "is not defined.")

    def __handle_human_join_response_message(self, mqtt_message):
        SRUP_human_join_response = pySRUPLib.SRUP_Human_Join_Response()
        SRUP_human_join_response.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_human_join_response.sender_id)
        if remote_key is not None:
            if SRUP_human_join_response.verify_keystring(remote_key):
                if "{:x}".format(SRUP_human_join_response.sender_id) == self.__server_id or self.__isServer:
                    if self.__on_human_join_response is not None:
                        id_value = SRUP_human_join_response.decrypt(self.__local_private_key)
                        self.__on_human_join_response(id_value)
                    else:
                        logging.error("Handler for Human Join Response is not defined...")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key.")

    def __handle_observed_join_request_message(self, mqtt_message):
        # Devices shouldn't receive join requests - so skip if not server...
        if self.__isServer:
            # Check the topic...to see if this is for us...
            if not bool(re.search('\ASRUP/servers/' + re.escape(self.__device_id) + '/\w+\Z', mqtt_message.topic)):
                # TODO: THROW A CUSTOM EXCEPTION?
                # We shouldn't be subscribed to another server's "JOIN" topic – so something went a bit wrong...
                logging.debug(mqtt_message.topic)
                logging.info("Message not for this server {}".format(re.findall('\ASRUP/servers/(\w+)/\w+\Z',
                                                                                mqtt_message.topic)))
            else:
                SRUP_observed_join_request = pySRUPLib.SRUP_Observed_Join_Request()
                SRUP_observed_join_request.deserialize(mqtt_message.payload)

                remote_key = self.__get_key(SRUP_observed_join_request.sender_id)
                if remote_key is None:
                    # We don't already have the keyC2_Server.accept_join(pending_device, ID_req=True) – so fetch it...
                    # If we get one, proceed – if not then log the error
                    if not self.__add_key_from_keyservice(SRUP_observed_join_request.sender_id):
                        # We can't find the key at the keyserver...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Sender ({}) could not be found at KeyEx lookup service".
                                      format(self.__convert_sender_format(SRUP_observed_join_request.sender_id)))
                        return
                    else:
                        remote_key = self.__get_key(SRUP_observed_join_request.sender_id)

                # Next we need to check to see if we have the device type - as we may need this later on...
                if self.__get_type(SRUP_observed_join_request.sender_id) is None:
                    self.__get_device_type(SRUP_observed_join_request.sender_id)

                if not SRUP_observed_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    joining_device = SRUP_observed_join_request.sender_id
                    hex_joining_device = hex(joining_device).lstrip('0x')
                    logging.info("OBSERVED JOIN Request received from {}".format(hex_joining_device))

                    observer = SRUP_observed_join_request.observer_id
                    hex_observer_device = hex(observer).lstrip('0x')
                    logging.info("Device requests observer {}".format(hex_observer_device))

                    # Add the device ID & token to pending joins...
                    self.__pending_joins[hex_joining_device] = SRUP_observed_join_request.token

                    # We'll now give the "user program" the chance to accept or reject the join request...
                    # To do this, we will call the registered callback function if there is one.
                    # We'll assume that if the user hasn't registered on – then a simple join request will always be
                    # (automatically) accepted – and responded to.

                    if self.__on_observed_join_request is not None:
                        # We'll call the user's function (providing them the device ID of the device).
                        # It'll then be up to the user-code to call the .join_accept(devID) method to accept the join.
                        # They can do this using device type – which can be retrieved by using the .device_types method
                        self.__on_observed_join_request(hex_joining_device, hex_observer_device)
                    else:
                        # Send srup_response_status_join_fail – since we have no handler for this kind of message.
                        self.fail_join(hex_joining_device)
                        logging.warning("Observed Moderated Join Message Rejected – __on_observed_join_request "
                                        "is not defined.")

    def __handle_observed_join_response_message(self, mqtt_message):
        SRUP_observed_join_response = pySRUPLib.SRUP_Observed_Join_Response()
        SRUP_observed_join_response.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_observed_join_response.sender_id)
        if remote_key is not None:
            if SRUP_observed_join_response.verify_keystring(remote_key):
                if "{:x}".format(SRUP_observed_join_response.sender_id) == self.__server_id or self.__isServer:
                    if self.__on_observed_join_response is not None:
                        id_value = SRUP_observed_join_response.decrypt(self.__local_private_key)
                        self.__on_observed_join_response(id_value)
                    else:
                        logging.error("Handler for Observed Join Response is not defined...")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key.")

    def __handle_observation_request_message(self, mqtt_message):
        SRUP_observation_request = pySRUPLib.SRUP_Observation_Request()
        SRUP_observation_request.deserialize(mqtt_message.payload)
        remote_key = self.__get_key(SRUP_observation_request.sender_id)
        if remote_key is not None:
            if SRUP_observation_request.verify_keystring(remote_key):
                if "{:x}".format(SRUP_observation_request.sender_id) == self.__server_id or self.__isServer:
                    if self.__on_observation_request is not None:
                        id_value = SRUP_observation_request.decrypt(self.__local_private_key)
                        joining_device = SRUP_observation_request.joining_device_id
                        hex_joining_device = hex(joining_device).lstrip('0x')
                        self.__observer_token = SRUP_observation_request.token
                        self.__on_observation_request(hex_joining_device, id_value)
                    else:
                        logging.error("Handler for Observation Request is not defined...")
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key.")

    def __handle_terminate_message(self, mqtt_message):
        if not self.__isServer:
            SRUP_Terminate_Command = pySRUPLib.SRUP_Terminate_Command()
            SRUP_Terminate_Command.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_Terminate_Command.sender_id)
            if remote_key is not None:
                if not SRUP_Terminate_Command.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    if "{:x}".format(SRUP_Terminate_Command.sender_id) == self.__server_id:
                        # We should also call the custom handler (if we have one),
                        # or just clear our device service_id property ...
                        if self.__on_terminate is None:
                            logging.info("TERMINATE Command received")
                            self.__server_id = None
                        else:
                            self.__on_terminate()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore...")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Server's can't handle terminate commands")

    def __handle_deregister_command_message(self, mqtt_message):
        if not self.__isServer:
            SRUP_Deregister_Command = pySRUPLib.SRUP_Deregister_Command()
            SRUP_Deregister_Command.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_Deregister_Command.sender_id)
            if remote_key is not None:
                if not SRUP_Deregister_Command.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    if "{:x}".format(SRUP_Deregister_Command.sender_id) == self.__server_id:
                        # We should also call the custom handler (if we have one),
                        # or just clear our device service_id property ...
                        if self.__on_terminate is None:
                            logging.info("DEREGISTER Command received")
                            self.__keystore.pop(self.server_id)
                            self.__server_id = None
                        else:
                            self.__on_terminate()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Server's can't handle terminate commands")

    def __handle_deregister_request_message(self, mqtt_message):
        if self.__isServer:
            SRUP_Deregister_Request = pySRUPLib.SRUP_Deregister_Request()
            SRUP_Deregister_Request.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_Deregister_Request.sender_id)
            if remote_key is not None:
                if not SRUP_Deregister_Request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    # Is this device, a device that we control?
                    if "{:x}".format(SRUP_Deregister_Request.sender_id) in self.__controlled_devices:
                        # We should also call the custom handler (if we have one),
                        # or just remove the key...
                        if self.__on_resign_request is None:
                            logging.info("DEREGISTER Request received")
                            self.__controlled_devices.remove("{:x}".format(SRUP_Deregister_Request.sender_id))
                            # TODO: REMOVE KEY! (&c.)
                        else:
                            self.__on_resign_request()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device's can't handle deregister requests")

    def __handle_resign_request_message(self, mqtt_message):
        if self.__isServer:
            SRUP_Resign_Request = pySRUPLib.SRUP_Resign_Request()
            SRUP_Resign_Request.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_Resign_Request.sender_id)
            if remote_key is not None:
                if not SRUP_Resign_Request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    # Is this device, a device that we control?
                    if "{:x}".format(SRUP_Resign_Request.sender_id) in self.__controlled_devices:
                        # We should also call the custom handler (if we have one),
                        # or just remove the device from the list, and drop the key...
                        if self.__on_resign_request is None:
                            logging.info("RESIGN Request received")
                            self.__controlled_devices.remove("{:x}".format(SRUP_Resign_Request.sender_id))
                            self.__keystore.pop(self.__convert_sender_format(SRUP_Resign_Request.sender_id))
                        else:
                            self.__on_resign_request()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.error("Sender not found in keystore.")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Devices's can't handle resign commands")

    def __handle_join_command_message(self, mqtt_message):
        # For a join command - we just need to check we're not a server...
        # We shouldn't check who the server is, as it's valid to process a join command from a server that is not our
        # 'current' server...
        if not self.__isServer:
            SRUP_Join_Command = pySRUPLib.SRUP_Join_Command()
            SRUP_Join_Command.deserialize(mqtt_message.payload)
            remote_key = self.__get_key(SRUP_Join_Command.sender_id)

            if remote_key is None:
                # We don't have the key - so go and get it...
                if self.__add_key_from_keyservice(SRUP_Join_Command.sender_id):
                    remote_key = self.__get_key(SRUP_Join_Command.sender_id)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.error("Key could not be retrieved from the key-service")
                    return

            if not SRUP_Join_Command.verify_keystring(remote_key):
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not verify using stored key.")
            else:
                # We've received a join command ...
                # We should also call the custom handler (if we have one), or just return a default
                # message, if we don't...
                if self.__on_join_command is None:
                    logging.info("JOIN Command received")
                    self.__server_id = "{:x}".format(SRUP_Join_Command.sender_id)
                else:
                    self.__on_join_command()
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Server cannot handle join command message")

    def __getToken(self):
        # Note that we wish the token to be a 128-bit UUID – rather than the 64-bit half-UUID's used for identity...
        return str(uuid.uuid4())

    def get_devices(self):
        # This is only valid for a server...
        if self.__isServer:
            return self.__controlled_devices
        else:
            return None

    def save_settings(self):
        config = configparser.ConfigParser()
        if not self.__isServer:
            config["Device"] = {"identity": self.__device_id,
                                "registration_url": self.__reg_url}
        else:
            config["Server"] = {"identity": self.__device_id,
                                "registration_url": self.__reg_url}

        if not self.__isServer:
            if self.__server_id is None:
                server_string = ""
            else:
                server_string = self.__server_id
            hex_seq_ids = {}
            for d_id, s_id in self.__seq_id.items():
                hex_seq_ids[self.__convert_sender_format(d_id)] = s_id

            config["SRUP"] = {"broker": "mqtt://" + self.__broker,
                              "server_identity": server_string,
                              "Seq_IDs": hex_seq_ids}
        else:
            hex_seq_ids = {}
            for d_id, s_id in self.__seq_id.items():
                hex_seq_ids[self.__convert_sender_format(d_id)] = s_id

            config["SRUP"] = {"broker": "mqtt://" + self.__broker,
                              "Seq_IDs": hex_seq_ids}

        remote_key_set = "{"
        for d_id, d_key in self.__keystore.items():
            remote_key_set += "'{}':'{}',".format(d_id, base64.b64encode(d_key.encode()).decode())
        remote_key_set += "}"

        config["Keys"] = {"local_public": self.__local_public_key,
                          "local_private": self.__local_private_key,
                          "remote_keys": remote_key_set}

        if self.__isServer:
            config["Devices"] = {"device_types": self.__deviceTypes}

        config["Access"] = {"key": self.__mqtt_key,
                            "certificate": self.__mqtt_cert,
                            "ca_certificate": self.__ca_cert}

        with open(self.__config_filename, 'w') as configfile:
            config.write(configfile)

    def __get_digest(self, filename, hasher, blocksize=65536):
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
        self.__on_action = f

    def on_data(self, f):
        self.__on_data = f

    def on_update(self, f):
        self.__on_update = f

    def on_update_success(self, f):
        self.__on_update_success = f

    def on_id_request(self, f):
        self.__on_id_request = f

    def on_terminate(self, f):
        self.__on_terminate = f

    def on_join_command(self, f):
        self.__on_join_command = f

    def on_join_request(self, f):
        self.__on_join_request = f

    def on_human_join_request(self, f):
        self.__on_human_join_request = f

    def on_human_join_response(self, f):
        self.__on_human_join_response = f

    def on_observed_join_request(self, f):
        self.__on_observed_join_request = f

    def on_observed_join_response(self, f):
        self.__on_observed_join_response = f

    def on_observation_request(self, f):
        self.__on_observation_request = f

    def on_join_refused(self, f):
        self.__on_join_refused = f

    def on_join_failed(self, f):
        self.__on_join_failed = f

    def on_join_succeed(self, f):
        self.__on_join_succeed = f

    def on_observed_join_succeed(self, f):
        self.__on_observed_join_succeed = f

    def on_observed_join_invalid(self, f):
        self.__on_observed_join_invalid = f

    def on_observed_join_fail(self, f):
        self.__on_observed_join_fail = f

    def on_resign_request(self, f):
        self.__on_resign_request = f

    def update_fetch_auth(self, a):
        self.__fetch_auth = a

    def update_filename(self, f):
        self.__fetch_filename = f

    def __on_initiate(self, SRUP_initiate_message):
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

    def __on_response(self, SRUP_response_message):
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
            self.__on_join_refused()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_join_fail():
            logging.info("RESPONSE Message – Join Failed...")
            self.__on_join_failed()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_join_success():
            self.__on_join_succeed()

        # Observed JOIN responses...
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_observed_join_valid():
            logging.info("RESPONSE Message – Observation Success")
            self.__on_observed_join_succeed()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_observed_join_invalid():
            logging.info("RESPONSE Message – Observation Invalid")
            self.__on_observed_join_invalid()
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_observed_join_fail():
            logging.info("RESPONSE Message – Observation Fail")
            self.__on_observed_join_fail()
        else:
            pass

    def __on_activate(self, SRUP_activate_message):
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
        SRUP_action_message.token = self.__getToken()

        # When we're sending a message – the sender ID is obviously the device ID of the "device" (or server) that's
        # sending the message... The sequence ID should be one more than the last seq_id used in a message to / from
        # that recipient...
        iTarget = int(target_id, 16)
        if iTarget not in self.__seq_id:
            self.__seq_id.update({iTarget: 0})
        self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
        s = self.__seq_id[iTarget]

        SRUP_action_message.sequence_id = s
        SRUP_action_message.sender_id = int(self.__device_id, 16)
        SRUP_action_message.action_id = action_id
        SRUP_action_message.sign(self.__local_private_key)
        serial_data = SRUP_action_message.serialize()
        if self.__isServer:
            pre_topic = target_id
        else:
            pre_topic = self.__device_id
        if serial_data is not None:
            topic = "SRUP/{}".format(pre_topic)
            self.__mqtt_client.publish(topic, serial_data)
            time.sleep(1)
            # self.__mqtt_client.loop_write()
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Message did not serialize")

    def send_SRUP_Data(self, target_id, data_id, data):
        SRUP_data_message = pySRUPLib.SRUP_Data()
        SRUP_data_message.token = self.__getToken()

        if target_id[:2] == "0x":
            target_id = target_id[2:]

        iTarget = int(target_id, 16)

        if iTarget not in self.__seq_id:
            self.__seq_id.update({iTarget: 0})
        self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
        s = self.__seq_id[iTarget]

        SRUP_data_message.sequence_id = s
        SRUP_data_message.sender_id = int(self.__device_id, 16)
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

        if SRUP_data_message.sign(self.__local_private_key):
            serial_data = SRUP_data_message.serialize()
            if self.__isServer:
                pre_topic = target_id
            else:
                pre_topic = self.__device_id
            if serial_data is not None:
                topic = "SRUP/{}".format(pre_topic)
                self.__mqtt_client.publish(topic, serial_data)
                time.sleep(1)
                # self.__mqtt_client.loop_write()
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.error("Message signature fail...")

    def send_SRUP_Initiate(self, target_id, url, digest):
        SRUP_init_message = pySRUPLib.SRUP_Initiate()
        SRUP_init_message.token = self.__getToken()

        iTarget = int(target_id, 16)
        if iTarget not in self.__seq_id:
            self.__seq_id.update({iTarget: 0})
        self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
        s = self.__seq_id[iTarget]

        SRUP_init_message.sequence_id = s
        SRUP_init_message.sender_id = int(self.__device_id, 16)
        SRUP_init_message.url = url
        SRUP_init_message.digest = digest
        SRUP_init_message.sign(self.__local_private_key)

        serial_data = SRUP_init_message.serialize()
        if self.__isServer:
            pre_topic = target_id
        else:
            pre_topic = self.__device_id

        if serial_data is not None:
            topic = "SRUP/{}".format(pre_topic)
            self.__mqtt_client.publish(topic, serial_data)
            time.sleep(1)
            # self.__mqtt_client.loop_write()
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Message did not serialize")

    def send_SRUP_Response(self, target_id, status, token):
        SRUP_response_message = pySRUPLib.SRUP_Response()
        # Note that this time we need to pass in a token rather than generate one...
        SRUP_response_message.token = token

        iTarget = int(target_id, 16)
        if iTarget not in self.__seq_id:
            self.__seq_id.update({iTarget: 0})
        self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
        s = self.__seq_id[iTarget]

        SRUP_response_message.sequence_id = s
        SRUP_response_message.sender_id = int(self.__device_id, 16)
        SRUP_response_message.status = status
        SRUP_response_message.sign(self.__local_private_key)

        serial_data = SRUP_response_message.serialize()
        if self.__isServer:
            pre_topic = target_id
        else:
            pre_topic = self.__device_id

        if serial_data is not None:
            topic = "SRUP/{}".format(pre_topic)
            self.__mqtt_client.publish(topic, serial_data)
            time.sleep(1)
            # self.__mqtt_client.loop_write()
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
        if iTarget not in self.__seq_id:
            self.__seq_id.update({iTarget: 0})
        self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
        s = self.__seq_id[iTarget]

        SRUP_activate_message.sequence_id = s
        SRUP_activate_message.sender_id = int(self.__device_id, 16)
        SRUP_activate_message.sign(self.__local_private_key)
        serial_data = SRUP_activate_message.serialize()
        if self.__isServer:
            pre_topic = target_id
        else:
            pre_topic = self.__device_id
        if serial_data is not None:
            topic = "SRUP/{}".format(pre_topic)
            self.__mqtt_client.publish(topic, serial_data)
            time.sleep(1)
            # self.__mqtt_client.loop_write()
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Message did not serialize")

    def send_SRUP_ID_Request(self, target_id):
        SRUP_id_request_message = pySRUPLib.SRUP_ID_Request()
        SRUP_id_request_message.token = self.__getToken()

        iTarget = int(target_id, 16)
        if iTarget not in self.__seq_id:
            self.__seq_id.update({iTarget: 0})
        self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
        s = self.__seq_id[iTarget]

        SRUP_id_request_message.sequence_id = s
        SRUP_id_request_message.sender_id = int(self.__device_id, 16)
        SRUP_id_request_message.sign(self.__local_private_key)
        serial_data = SRUP_id_request_message.serialize()

        if self.__isServer:
            pre_topic = target_id
        else:
            pre_topic = self.__device_id

        if serial_data is not None:
            topic = "SRUP/{}".format(pre_topic)
            self.__mqtt_client.publish(topic, serial_data)
            time.sleep(1)
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Message did not serialize")

    def send_SRUP_simple_join(self):
        # Simple join is sent to the "nominated" server...received from the KeyEx service during registration
        # The identity of the server is stored in the class property __server_id
        if not self.__isServer:
            SRUP_Join_Request = pySRUPLib.SRUP_Join_Request()
            SRUP_Join_Request.token = self.__getToken()

            iTarget = int(self.__server_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            # We must also get the server's key – if we don't already have it...
            if not iTarget in self.__keystore:
                self.__add_key_from_keyservice(iTarget)

            SRUP_Join_Request.sequence_id = s
            SRUP_Join_Request.sender_id = int(self.__device_id, 16)
            SRUP_Join_Request.sign(self.__local_private_key)
            serial_data = SRUP_Join_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/servers/{}/{}".format(self.__server_id, self.__device_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending JOIN Request to {}".format(self.__server_id))
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
        if not self.__isServer:
            SRUP_Human_Join_Request = pySRUPLib.SRUP_Human_Join_Request()
            SRUP_Human_Join_Request.token = self.__getToken()

            iTarget = int(self.__server_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            # We must also get the server's key – if we don't already have it...
            if not iTarget in self.__keystore:
                self.__add_key_from_keyservice(iTarget)

            SRUP_Human_Join_Request.sequence_id = s
            SRUP_Human_Join_Request.sender_id = int(self.__device_id, 16)
            SRUP_Human_Join_Request.sign(self.__local_private_key)
            serial_data = SRUP_Human_Join_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/servers/{}/{}".format(self.__server_id, self.__device_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending HUMAN JOIN Request to {}".format(self.__server_id))
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
        if self.__isServer:
            SRUP_HJ_Response = pySRUPLib.SRUP_Human_Join_Response()

            iTarget = int(target_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            SRUP_HJ_Response.sequence_id = s
            SRUP_HJ_Response.sender_id = int(self.__device_id, 16)
            SRUP_HJ_Response.token = self.__getToken()

            # Generate a new UUID for the ID value
            id_val = uuid.uuid4().hex
            time.sleep(0.5)
            SRUP_HJ_Response.encrypt_keystring(id_val, self.__get_key(target_id))

            SRUP_HJ_Response.sign(self.__local_private_key)
            serial_data = SRUP_HJ_Response.serialize()

            if serial_data is not None:
                topic = "SRUP/{}".format(target_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending HUMAN JOIN RESPONSE to {}".format(target_id))
                time.sleep(1)
                self.__pending_joins[target_id] = SRUP_HJ_Response.token
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
        if not self.__isServer:
            SRUP_Observed_Join_Request = pySRUPLib.SRUP_Observed_Join_Request()
            SRUP_Observed_Join_Request.token = self.__getToken()

            iTarget = int(self.__server_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            # We must also get the server's key – if we don't already have it...
            if not iTarget in self.__keystore:
                self.__add_key_from_keyservice(iTarget)

            SRUP_Observed_Join_Request.sequence_id = s
            SRUP_Observed_Join_Request.sender_id = int(self.__device_id, 16)
            SRUP_Observed_Join_Request.observer_id = int(observer_id, 16)
            SRUP_Observed_Join_Request.sign(self.__local_private_key)
            serial_data = SRUP_Observed_Join_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/servers/{}/{}".format(self.__server_id, self.__device_id)
                self.__mqtt_client.publish(topic, serial_data)
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
        if self.__isServer:
            SRUP_Observed_Join_Response = pySRUPLib.SRUP_Observed_Join_Response()

            iTarget = int(target_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            SRUP_Observed_Join_Response.sequence_id = s
            SRUP_Observed_Join_Response.sender_id = int(self.__device_id, 16)
            SRUP_Observed_Join_Response.token = self.__getToken()

            # Generate a new UUID for the ID value
            id_val = uuid.uuid4().hex
            time.sleep(0.5)
            SRUP_Observed_Join_Response.encrypt_keystring(id_val, self.__get_key(target_id))

            SRUP_Observed_Join_Response.sign(self.__local_private_key)
            serial_data = SRUP_Observed_Join_Response.serialize()

            if serial_data is not None:
                topic = "SRUP/{}".format(target_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending OBSERVED JOIN RESPONSE to {}".format(target_id))
                time.sleep(1)
                self.__pending_joins[target_id] = SRUP_Observed_Join_Response.token
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
        if self.__isServer:
            SRUP_Observation_Request = pySRUPLib.SRUP_Observation_Request()

            # The target ID here is the ID of the observer... since that's where we're sending the message...
            iTarget = int(target_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            SRUP_Observation_Request.sequence_id = s
            SRUP_Observation_Request.sender_id = int(self.__device_id, 16)
            SRUP_Observation_Request.token = self.__getToken()

            SRUP_Observation_Request.joining_device_id = int(joining_device, 16)

            SRUP_Observation_Request.encrypt_keystring(id_val, self.__get_key(target_id))

            SRUP_Observation_Request.sign(self.__local_private_key)
            serial_data = SRUP_Observation_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/{}".format(target_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending OBSERVATION REQUEST to {}".format(target_id))
                time.sleep(1)
                return id_val
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Observation Request message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Only server can send Observation Requests...")

    def send_SRUP_Terminate(self, target_id):
        # We can only send a terminate if we're a server...
        if self.__isServer:
            # We can only send a terminate message to a device that we control...
            if target_id in self.__controlled_devices:
                SRUP_Terminate_Command = pySRUPLib.SRUP_Terminate_Command()
                SRUP_Terminate_Command.token = self.__getToken()

                iTarget = int(target_id, 16)
                if iTarget not in self.__seq_id:
                    self.__seq_id.update({iTarget: 0})
                self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
                s = self.__seq_id[iTarget]

                SRUP_Terminate_Command.sequence_id = s
                SRUP_Terminate_Command.sender_id = int(self.__device_id, 16)
                SRUP_Terminate_Command.sign(self.__local_private_key)
                serial_data = SRUP_Terminate_Command.serialize()

                if serial_data is not None:
                    # Since we're about to terminate the device – we should remove it from the controlled_devices list
                    # We already know it's there - as we checked earlier.
                    self.__controlled_devices.remove(target_id)
                    topic = "SRUP/{}".format(target_id)
                    self.__mqtt_client.publish(topic, serial_data)
                    logging.info("Sending TERMINATE Command to {}".format(target_id))
                    time.sleep(1)
                    # Lastly we should remove the target device from our keystore...
                    self.__keystore.pop(target_id)
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
        if self.__isServer:
            # We can't send a join command to a device that we already control...
            if target_id not in self.__controlled_devices:
                SRUP_Join_Command = pySRUPLib.SRUP_Join_Command()
                SRUP_Join_Command.token = self.__getToken()

                iTarget = int(target_id, 16)
                if iTarget not in self.__seq_id:
                    self.__seq_id.update({iTarget: 0})
                self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
                s = self.__seq_id[iTarget]

                SRUP_Join_Command.sequence_id = s
                SRUP_Join_Command.sender_id = int(self.__device_id, 16)
                SRUP_Join_Command.device_id = iTarget
                SRUP_Join_Command.sign(self.__local_private_key)
                serial_data = SRUP_Join_Command.serialize()

                if serial_data is not None:
                    # As we're adding the join we can add this to the controlled_devices list...
                    self.__controlled_devices.append(target_id)
                    topic = "SRUP/{}".format(target_id)
                    self.__mqtt_client.publish(topic, serial_data)
                    logging.info("Sending JOIN Command to {}".format(target_id))
                    time.sleep(1)
                    # We also need to subscribe to the topic for the device we're just sent to...
                    self.__mqtt_client.subscribe("SRUP/{}".format(target_id))
                    # ... and add the key for this device to the keystore...
                    if not self.__add_key_from_keyservice(target_id):
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
        if not self.__isServer:
            SRUP_Resign_Request = pySRUPLib.SRUP_Resign_Request()
            SRUP_Resign_Request.token = self.__getToken()

            iTarget = int(self.__server_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            SRUP_Resign_Request.sequence_id = s
            SRUP_Resign_Request.sender_id = int(self.__device_id, 16)
            SRUP_Resign_Request.sign(self.__local_private_key)
            serial_data = SRUP_Resign_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/{}".format(self.__device_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending Resign request to server {}".format(self.__server_id))

                # As we're a device – we won't drop the server key as we can presume we might want it again in the
                # future ... but we should clear our (current) server_id
                self.__server_id = None
                time.sleep(1)

            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Devices's cannot send resign requests...")

    def send_SRUP_Deregister_Request(self):
        # We can only send a deregister request if we're not a server...
        if not self.__isServer:
            SRUP_Deregister_Request = pySRUPLib.SRUP_Deregister_Request()
            SRUP_Deregister_Request.token = self.__getToken()

            iTarget = int(self.__server_id, 16)
            if iTarget not in self.__seq_id:
                self.__seq_id.update({iTarget: 0})
            self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
            s = self.__seq_id[iTarget]

            SRUP_Deregister_Request.sequence_id = s
            SRUP_Deregister_Request.sender_id = int(self.__device_id, 16)
            SRUP_Deregister_Request.sign(self.__local_private_key)
            serial_data = SRUP_Deregister_Request.serialize()

            if serial_data is not None:
                topic = "SRUP/{}".format(self.__device_id)
                self.__mqtt_client.publish(topic, serial_data)
                logging.info("Sending Deregister request to server {}".format(self.__server_id))

                # Since we're about to deregister we should clear our server_id and drop the key
                self.__keystore.pop(self.server_id)
                self.__server_id = None
                time.sleep(1)
            else:
                # TODO: THROW A CUSTOM EXCEPTION
                logging.warning("Message did not serialize")
        else:
            # We can't request resignation if we are a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Devices's cannot send deregister requests...")

    def send_SRUP_Deregister_Command(self, target_id):
        # We can only send a deregister command if we're a server...
        if self.__isServer:
            # We can only send a deregister command message to a device that we control...
            if target_id in self.__controlled_devices:
                SRUP_Deregister_Command = pySRUPLib.SRUP_Deregister_Command()
                SRUP_Deregister_Command.token = self.__getToken()

                iTarget = int(target_id, 16)
                if iTarget not in self.__seq_id:
                    self.__seq_id.update({iTarget: 0})
                self.__seq_id.update({iTarget: self.__seq_id[iTarget]+1})
                s = self.__seq_id[iTarget]

                SRUP_Deregister_Command.sequence_id = s
                SRUP_Deregister_Command.sender_id = int(self.__device_id, 16)
                SRUP_Deregister_Command.sign(self.__local_private_key)
                serial_data = SRUP_Deregister_Command.serialize()

                if serial_data is not None:
                    # Since we're about to deregister the device – we should remove it from the controlled_devices list
                    # We already know it's there - as we checked earlier.
                    self.__controlled_devices.remove(target_id)
                    topic = "SRUP/{}".format(target_id)
                    self.__mqtt_client.publish(topic, serial_data)
                    logging.info("Sending DEREGISTER Command to {}".format(target_id))
                    self.__keystore.pop(target_id)
                    time.sleep(1)
                else:
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not serialize")
        else:
            # We can't request termination if we're not a server...
            # TODO: THROW A CUSTOM EXCEPTION
            # TODO: Log this!
            logging.warning("Only servers can send deregister commands...")

    def accept_join(self, deviceID, ID_req=False):
        if deviceID in self.__pending_joins:
            # To accept the join; the next step is to subscribe to the topic corresponding to the device;
            # and send a response message on that topic.
            self.__mqtt_client.subscribe("SRUP/{}/#".format(deviceID))
            SRUP_response_message = pySRUPLib.SRUP_Response()
            status = SRUP_response_message.srup_response_status_join_success()

            # Lastly we add the new device to the controlled_devices list.
            self.__controlled_devices.append("{}".format(deviceID))

            self.send_SRUP_Response(deviceID, status, self.__pending_joins[deviceID])
            # Now we've done with the token – we should delete the dictionary entry...
            del self.__pending_joins[deviceID]

            if ID_req:
                self.send_SRUP_ID_Request(deviceID)

        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device ID {:x} not found in pending joins.".format(deviceID))

    def refuse_join(self, deviceID):
        if deviceID in self.__pending_joins:
            # To refuse the join we just need to send a response message.
            # (We'll use the device's topic – but *we* don't need to be subscribed to send it)...
            SRUP_response_message = pySRUPLib.SRUP_Response()
            status = SRUP_response_message.srup_response_status_join_refused()
            self.send_SRUP_Response(deviceID, status, self.__pending_joins[deviceID])

            # Now we've done with the token – we should delete the dictionary entry...
            # The new join (if we get one) will use a new token.
            del self.__pending_joins[deviceID]

        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device ID {:x} not found in pending joins.".format(deviceID))

    def fail_join(self, deviceID):
        if deviceID in self.__pending_joins:
            # To reject the join we just need to send a 'join fail' response message.
            # (We'll use the device's topic – but *we* don't need to be subscribed to send it)...
            SRUP_response_message = pySRUPLib.SRUP_Response()
            status = SRUP_response_message.srup_response_status_join_fail()
            self.send_SRUP_Response(deviceID, status, self.__pending_joins[deviceID])

            # Now we've done with the token – we should delete the dictionary entry...
            # The new join (if we get one) will use a new token.
            del self.__pending_joins[deviceID]
        else:
            # TODO: THROW A CUSTOM EXCEPTION
            logging.warning("Device ID {:x} not found in pending joins.".format(deviceID))

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


# Now that we have defined the base-class, we will derive two subclasses (one for clients - e.g. devices),
# and one for servers...
# They are both very similar (as you'd expect) - but there are a few differences.
# Not least of which is the degree to which servers are not self-constructing - but rather need key exchange,
# and the establishment of their configuration files to be carried out manually, outside of the pySRUP constructs.
class Client (SRUP):
    def __init__(self, config_filename, base_registration_url, device_type=None):
        config = configparser.ConfigParser()
        settings = {}
        try:
            with open(config_filename) as f:
                config.read_file(f)

        except IOError as iox:
            # If errno == 2 (File Not Found) then do KeyEx...
            if iox.errno == 2:
                KeyEx(config_filename, base_registration_url, device_type)
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

        super().__init__(settings['broker'], settings['identity'], settings['local_private'],
                         settings['local_public'], settings['remote_keys'], None, settings['Seq_IDs'],
                         settings['registration_url'], settings['server_identity'], settings['ca_certificate'],
                         settings['certificate'], settings['key'], config_filename, False)


# There are a few differences between devices and servers...
# The most significant one is that we do not do key exchange for servers; rather we require this to be done outside
# of the pySRUP construct. This is to ensure that only legitimate server's can be issued a server certificate.
# There would be a significant security vulnerability if this protection wasn't in place.
class Server (SRUP):
    def __init__(self, config_filename):
        config = configparser.ConfigParser()
        settings = {}
        try:
            with open(config_filename) as f:
                config.read_file(f)

        except IOError as iox:
            logging.error("The specified server config file ({}) couldn't be opened".format(config_filename))
            raise

        else:
            config_to_load = {"Server": ["identity", "registration_url"], "SRUP": ["broker"],
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


        super().__init__(settings['broker'], settings['identity'], local_private_key=settings['local_private'],
                         local_public_key=settings['local_public'], remote_public_keys=settings['remote_keys'],
                         remote_device_types=settings['device_types'], start_seq_id=settings['Seq_IDs'],
                         registration_url=settings['registration_url'], server_id=None,
                         ca_cert=settings['ca_certificate'], cert=settings['certificate'], key=settings['key'],
                         config_filename=config_filename, server=True)

