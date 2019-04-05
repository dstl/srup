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
SRUP_TERMINATE_COMMAND_MESSAGE_TYPE = pySRUPLib.__terminate_command_message_type()
SRUP_JOIN_COMMAND_MESSAGE_TYPE = pySRUPLib.__join_command_message_type()
SRUP_RESIGN_REQUEST_MESSAGE_TYPE = pySRUPLib.__resign_request_message_type()
SRUP_DEREGISTER_REQUEST_MESSAGE_TYPE = pySRUPLib.__deregister_request_message_type()
SRUP_DERESISTER_COMMNAND_MESSAGE_TYPE = pySRUPLib.__deregister_command_message_type()

# As of the current version of the pySRUP code (Feb 2019) we'll exclusively use the key-string
# rather than key file for non-local keys...
# The underpinning C++ library will continue to support both – as will the direct pySRUPLib port to Python.
# (Not least so that we can use key files for the local keys...)
# For this to work, we need to add the key to the in-memory data structure in the event of the
# JOIN, so that for any other message handler, we can assume that (for any joined device) the
# key will (should) be in the keystore.


class SRUP:

    __keyExRoute = '/KeyEx/register/get_key/'

    def __init__(self, broker, device_id, local_private_key, local_public_key, remote_public_keys, start_seq_id,
                 registration_url, server_id, ca_cert, cert, key, config_filename, server=False):
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
        self.__on_resign_request = None
        self.__on_deregister_request = None
        self.__on_degregister_command = None
        self.__config_filename = config_filename
        self.__mqtt_client = mqtt.Client(client_id="SRUP Client: {}".format(device_id))
        self.__mqtt_client.on_connect = self.__on_connect
        self.__mqtt_client.on_message = self.__on_mqtt_message
        self.__mqtt_client.tls_set(ca_certs=self.__ca_cert, certfile=self.__mqtt_cert, keyfile=self.__mqtt_key)
        self.__pySRUP_Version = lambda: 1.0
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
                        else:
                            # We have received a message type that we can't handle...
                            # TODO: THROW A CUSTOM EXCEPTION
                            logging.warning("Invalid message type or format")
                            logging.warning(SRUP_generic_message.msg_type)
                            logging.warning(SRUP_generic_message.sequence_id)

                    else:
                        # We have an invalid sequence ID...
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.warning("Sequence ID 0x{:02X} is invalid".format(SRUP_generic_message.sequence_id))
                        logging.debug("Message Type: {}".format(SRUP_generic_message.msg_type))
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

                if not SRUP_join_request.verify_keystring(remote_key):
                    # TODO: THROW A CUSTOM EXCEPTION
                    logging.warning("Message did not verify using stored key.")
                else:
                    joining_device = SRUP_join_request.sender_id
                    logging.info("JOIN Request received from {:x}".format(joining_device))

                    # For a simple join request we'll always accept; so next we subscribe to the
                    # topic corresponding to the device; and send a response message on that topic.
                    self.__mqtt_client.subscribe("SRUP/{:x}/#".format(joining_device))
                    SRUP_response_message = pySRUPLib.SRUP_Response()
                    status = SRUP_response_message.srup_response_status_join_success()
                    self.send_SRUP_Response(hex(joining_device), status, SRUP_join_request.token)

                    # Lastly (since we know we  must be a server to have gotten this far) we
                    # add the new device to the controlled_devices list.
                    self.__controlled_devices.append("{:x}".format(joining_device))

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
            config["SRUP"] = {"broker": "mqtt://" + self.__broker,
                              "server_identity": server_string,
                              "Seq_IDs": self.__seq_id}
        else:
            config["SRUP"] = {"broker": "mqtt://" + self.__broker,
                              "Seq_IDs": self.__seq_id}

        remote_key_set = "{"
        for d_id, d_key in self.__keystore.items():
            remote_key_set += "'{}':'{}'".format(d_id, base64.b64encode(d_key.encode()).decode())
        remote_key_set += "}"

        config["Keys"] = {"local_public": self.__local_public_key,
                          "local_private": self.__local_private_key,
                          "remote_keys": remote_key_set}

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
        # At the moment the only types of response we can do anything with is the 'update' responses...
        logging.info("RESPONSE MESSAGE Received")
        if SRUP_response_message.status == SRUP_response_message.srup_response_status_update_success():
            target = hex(SRUP_response_message.sender_id)[2:]
            self.__on_update_success(token=SRUP_response_message.token, target=target)
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_update_fail_server():
            pass
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_update_fail_file():
            pass
        elif SRUP_response_message.status == SRUP_response_message.srup_response_status_update_fail_digest():
            pass
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
            logging.warning("Only servers can send terminate commands...")

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


class Client (SRUP):
    def __init__(self, config_filename, base_registration_url):
        config = configparser.ConfigParser()
        settings = {}
        try:
            with open(config_filename) as f:
                config.read_file(f)

        except IOError as iox:
            # If errno == 2 (File Not Found) then do KeyEx...
            if iox.errno == 2:
                KeyEx(config_filename, base_registration_url)
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
                        logging.error("Config file could not be loaded")
                        raise

                    # ... or the specific option is missing
                    except configparser.NoOptionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        logging.error("Config file could not be loaded")
                        raise
            try:
                seqids = config.get("SRUP", "Seq_IDs")
                settings['Seq_IDs'] = ast.literal_eval(seqids)

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
                         settings['local_public'], settings['remote_keys'], settings['Seq_IDs'],
                         settings['registration_url'], settings['server_identity'], settings['ca_certificate'],
                         settings['certificate'], settings['key'], config_filename, False)


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

            # Now some special cases – loading dictionaries for Seq_IDs & remote keys...
            # Noting that either of these could be "blank" (or not included).
            # First the sequence IDs...
            try:
                seqids = config.get("SRUP", "Seq_IDs")
                settings['Seq_IDs'] = ast.literal_eval(seqids)

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

        super().__init__(settings['broker'], settings['identity'], local_private_key=settings['local_private'],
                         local_public_key=settings['local_public'], remote_public_keys=settings['remote_keys'],
                         start_seq_id = settings['Seq_IDs'], registration_url=settings['registration_url'],
                         server_id=None, ca_cert=settings['ca_certificate'], cert=settings['certificate'],
                         key=settings['key'], config_filename=config_filename, server=True)
