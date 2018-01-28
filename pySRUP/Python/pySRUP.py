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

from KeyEx_Client import KeyEx

SRUP_GENERIC_MESSAGE_TYPE = pySRUPLib.__generic_message_type()
SRUP_ACTION_MESSAGE_TYPE = pySRUPLib.__action_message_type()
SRUP_DATA_MESSAGE_TYPE = pySRUPLib.__data_message_type()
SRUP_INITIATE_MESSAGE_TYPE = pySRUPLib.__initiate_message_type()
SRUP_RESPONSE_MESSAGE_TYPE = pySRUPLib.__response_message_type()
SRUP_ACTIVATE_MESSAGE_TYPE = pySRUPLib.__activate_message_type()


class SRUP:
    def __init__(self, broker, device_id, device_private_key, device_public_key, server_public_key, start_seq_id,
                 registration_url, server_id, ca_cert, cert, key, config_filename, server=False):
        self.__isServer = server
        self.__seq_id = start_seq_id
        self.__device_id = device_id
        # Strip the mqtt:// part from the broker URL
        if broker[:7] == 'mqtt://':
            broker = broker[7:]
        self.__broker = broker
        self.__local_private_key = device_private_key
        self.__remote_public_key = server_public_key
        self.__ca_cert = ca_cert
        self.__mqtt_cert = cert
        self.__mqtt_key = key
        self.__reg_url = registration_url
        self.__server_id = server_id
        self.__local_public_key = device_public_key
        self.__open_update_tokens = {}
        self.__on_action = None
        self.__on_data = None
        self.__on_update = None
        self.__on_update_success = None
        self.__fetch_auth = None
        self.__fetch_filename = None
        self.__config_filename = config_filename
        self.__mqtt_client = mqtt.Client(client_id="SRUP Client: {}".format(device_id))
        self.__mqtt_client.on_connect = self.__on_connect
        self.__mqtt_client.on_message = self.__on_message
        self.__mqtt_client.tls_set(ca_certs=self.__ca_cert, certfile=self.__mqtt_cert, keyfile=self.__mqtt_key)

    def __enter__(self):
        self.__mqtt_client.connect(self.__broker, 8883, 60)
        self.__mqtt_client.loop_start()

    def __exit__(self, *args):
        self.__mqtt_client.disconnect()
        self.__mqtt_client.loop_stop()

    def __on_connect(self, client, userdata, flags, rc):
        # If we're a server then we need to subscribe to the wildcarded parent channel...
        # whereas if we're a device we need to subscribe only to "our" channel.
        if self.__isServer:
            client.subscribe("SRUP/#")
        else:
            client.subscribe("SRUP/{}".format(self.__device_id))
        # And sleep for a moment - just to let Paho catch-up before we move on.
        time.sleep(0.5)

    def __on_message(self, client, userdata, msg):
        # First check if the message is even for us...
        # Remembering that server's are wild...
        topic = None
        ch_topic = msg.topic
        if ch_topic[0:5] == 'SRUP/':
            topic = ch_topic[5:]

        # First check if the message is for us (or if we're a server read it anyway)
        if topic == self.__device_id or self.__isServer:
            SRUP_generic_message = pySRUPLib.SRUP_Generic()

            # if if deserializes then it's probably a SRUP message...
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
                        self.__seq_id[SRUP_generic_message.sender_id] = SRUP_generic_message.sequence_id

                        msg_type = SRUP_generic_message.msg_type
                        if msg_type == SRUP_ACTION_MESSAGE_TYPE:
                            SRUP_action_message = pySRUPLib.SRUP_Action()
                            SRUP_action_message.deserialize(msg.payload)
                            if SRUP_action_message.verify(self.__remote_public_key):
                                self.__on_action(SRUP_action_message)
                            else:
                                # TODO: THROW A CUSTOM EXCEPTION
                                print("Message did not verify using {}".format(self.__remote_public_key))

                        elif msg_type == SRUP_DATA_MESSAGE_TYPE:
                            SRUP_data_message = pySRUPLib.SRUP_Data()
                            SRUP_data_message.deserialize(msg.payload)
                            if SRUP_data_message.verify(self.__remote_public_key):
                                self.__on_data(SRUP_data_message)
                            else:
                                # TODO: THROW A CUSTOM EXCEPTION
                                print("Message did not verify using {}".format(self.__remote_public_key))

                        elif msg_type == SRUP_INITIATE_MESSAGE_TYPE:
                            # Devices can't send init messages – so skip this if we're a server...
                            if not self.__isServer:
                                SRUP_initiate_message = pySRUPLib.SRUP_Initiate()
                                SRUP_initiate_message.deserialize(msg.payload)
                                if SRUP_initiate_message.verify(self.__remote_public_key):
                                    self.__on_initiate(SRUP_initiate_message)
                                else:
                                    # TODO: THROW A CUSTOM EXCEPTION
                                    print("Message did not verify using {}".format(self.__remote_public_key))

                        elif msg_type == SRUP_RESPONSE_MESSAGE_TYPE:
                            SRUP_response_message = pySRUPLib.SRUP_Response()
                            SRUP_response_message.deserialize(msg.payload)
                            if SRUP_response_message.verify(self.__remote_public_key):
                                self.__on_response(SRUP_response_message)
                            else:
                                # TODO: THROW A CUSTOM EXCEPTION
                                print("Message did not verify using {}".format(self.__remote_public_key))

                        elif msg_type == SRUP_ACTIVATE_MESSAGE_TYPE:
                            # Devices can't send activate messages either – so again, we'll skip if we're a server.
                            if not self.__isServer:
                                SRUP_activate_message = pySRUPLib.SRUP_Activate()
                                SRUP_activate_message.deserialize(msg.payload)
                                if SRUP_activate_message.verify(self.__remote_public_key):
                                    self.__on_activate(SRUP_activate_message)
                                else:
                                    # TODO: THROW A CUSTOM EXCEPTION
                                    print("Message did not verify using {}".format(self.__remote_public_key))
                        else:
                            # We have received a message type that we can't handle...
                            # TODO: THROW A CUSTOM EXCEPTION
                            print("Invalid message type or format")
                            print(SRUP_generic_message.sequence_id)

                    else:
                        # TODO: THROW A CUSTOM EXCEPTION
                        print("Sequence ID 0x{:02X} is invalid".format(SRUP_generic_message.sequence_id))
                        # print("Message Type: {}".format(SRUP_generic_message.msg_type))
                else:
                    pass
                    # This is our own message – so ignore it...
            else:
                pass
                # TODO: Not a SRUP Message ...
        else:
            pass
            # Not a message meant for us – so skip it...

    def __getToken(self):
        # Note that we wish the token to be a 128-bit UUID – rather than the 64-bit half-UUID's used for identity...
        return str(uuid.uuid4())

    def save_settings(self):
        config = configparser.ConfigParser()
        if not self.__isServer:
            config["Device"] = {"identity": self.__device_id,
                                "registration_url": self.__reg_url}
        else:
            config["Server"] = {"identity": self.__device_id}

        if not self.__isServer:
            config["SRUP"] = {"broker": "mqtt://" + self.__broker,
                              "server_identity": self.__server_id,
                              "Seq_IDs": self.__seq_id}
        else:
            config["SRUP"] = {"broker": "mqtt://" + self.__broker,
                              "Seq_IDs": self.__seq_id}

        if not self.__isServer:
            config["Keys"] = {"device_public": self.__local_public_key,
                              "device_private": self.__local_private_key,
                              "server": self.__remote_public_key}
        else:
            config["Keys"] = {"server_public": self.__local_public_key,
                              "server_private": self.__local_private_key,
                              "device_public": self.__remote_public_key}

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

    def update_fetch_auth(self, a):
        self.__fetch_auth = a

    def update_filename(self, f):
        self.__fetch_filename = f

    def __on_initiate(self, SRUP_initiate_message):
        # print("INITIATE MESSAGE Received")
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
        # print("RESPONSE MESSAGE Received")
        if SRUP_response_message.status == SRUP_response_message.srup_response_status_update_success():
            self.__on_update_success(token=SRUP_response_message.token)
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
        # print("ACTIVATE MESSAGE Received")
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
            print("Message did not serialize")

    def send_SRUP_Data(self, target_id, data_id, data):
        SRUP_data_message = pySRUPLib.SRUP_Data()
        SRUP_data_message.token = self.__getToken()

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

        SRUP_data_message.sign(self.__local_private_key)
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
            print("Message did not serialize")

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
        SRUP_init_message.target = target_id
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
            print("Message did not serialize")

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
        SRUP_response_message.target = target_id
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
            print("Message did not serialize")

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
            print("Message did not serialize")


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
                    print("The config file couldn't be created or opened after creation")
                    raise
            else:
                raise

        finally:
            config_to_load = {"Device": ["identity", "registration_url"], "SRUP": ["broker", "server_identity"],
                              "Keys": ["device_public", "device_private", "server"],
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
                        print("Config file could not be loaded")
                        raise

                    # ... or the specific option is missing
                    except configparser.NoOptionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        print("Config file could not be loaded")
                        raise
            try:
                seqids = config.get("SRUP", "Seq_IDs")
                settings['Seq_IDs'] = ast.literal_eval(seqids)

            # Note the same fatal error if the section is missing
            # (although if we've got here that shouldn't be possible!)
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                print("Config file could not be loaded")
                raise

            # Generate empty if not specified.
            except configparser.NoOptionError:
                seqids = "{}"
                settings['Seq_IDs'] = ast.literal_eval(seqids)

        if settings['registration_url'] != base_registration_url:
            # TODO: THROW A CUSTOM EXCEPTION
            print("Registration URL mis-match...")

        super().__init__(settings['broker'], settings['identity'], settings['device_private'],
                         settings['device_public'], settings['server'], settings['Seq_IDs'],
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
            # If errno == 2 (File Not Found) then do KeyEx...
                print("The config file couldn't be created or opened after creation")
                raise

        else:
            config_to_load = {"Server": ["identity"], "SRUP": ["broker"],
                              "Keys": ["server_public", "server_private", "device_public"],
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
                        print("Config file could not be loaded")
                        raise

                    # ... or the specific option is missing
                    except configparser.NoOptionError:
                        # TODO: THROW A CUSTOM EXCEPTION
                        print("Config file could not be loaded")
                        raise
            try:
                seqids = config.get("SRUP", "Seq_IDs")
                settings['Seq_IDs'] = ast.literal_eval(seqids)

            # Note the same fatal error if the section is missing
            # (although if we've got here that shouldn't be possible!)
            except configparser.NoSectionError:
                # TODO: THROW A CUSTOM EXCEPTION
                print("Config file could not be loaded")
                raise

            # Generate empty if not specified.
            except configparser.NoOptionError:
                seqids = "{}"
                settings['Seq_IDs'] = ast.literal_eval(seqids)

        super().__init__(settings['broker'], settings['identity'], settings['server_private'],
                         settings['server_public'], settings['device_public'], settings['Seq_IDs'],
                         registration_url=None, server_id=None, ca_cert=settings['ca_certificate'],
                         cert=settings['certificate'], key=settings['key'], config_filename=config_filename,
                         server=True)
