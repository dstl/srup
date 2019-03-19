from flask import Flask
from flask import request

import json
import base64

import configparser
import argparse

import logging
import coloredlogs

import database_functions
import KeyEx_helpers
import KeyExReturn

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
import datetime

config = configparser.ConfigParser()

# We'll take a config file name from the command-line, if there is one, or we'll use the default...
DEFAULT_FILENAME = "server.cfg"

# Note that we'll only try to use argparse if we're running directly (__name__=='__main__') – otherwise we'll
# use the default
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SRUP Key Exchange Server application")
    parser.add_argument("config_file", nargs='?', default=DEFAULT_FILENAME, help="The optional config file to be loaded.  \
                              The file " + DEFAULT_FILENAME + " will be loaded if a config_file name is not specified")
    args = parser.parse_args()
    config_file = args.config_file
else:
    config_file = DEFAULT_FILENAME

# Now that we have the config file name, we'll check to see we can open it...
try:
    with open(config_file) as f:
        config.read_file(f)
except IOError:
    print("Config File: {} could not be opened".format(config_file))
    exit(-1)

# If the file is good; we'll setup the log file with the specified (or a default) name...
# Note that because of the fallback - we don't need the try..catch blocking used elsewhere, for this 'get'.
LOG_FILE = config.get("Settings", "logfile", fallback="logfile.log")

# For logging, we'll use 'logging' for writing to a file, and also colorlogs writing to the screen.
# We'll only log WARNING or higher to the screen.
# Flask will pick up our log and add to it too...
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t\t%(message)s')

logfile = logging.FileHandler(LOG_FILE)
logfile.setLevel(logging.INFO)
logfile.setFormatter(formatter)
logger.addHandler(logfile)

coloredlogs.DEFAULT_FIELD_STYLES['levelname']={'color': 'white'}
coloredlogs.DEFAULT_LOG_FORMAT = '%(asctime)s\t%(levelname)s\t\t%(message)s'
coloredlogs.install(level='WARNING')

# Now we have the logging up and running, we can try to read the remaining configuration parameters from the config
# file – with fatal errors if any of the critical settings are missing...
global_settings = KeyEx_helpers.get_config(logging, config)

# ... and now unpack the dictionary to "constants".
MQTT_BROKER = global_settings['broker']
DATABASE_FILE = global_settings['database']
SERVER_PUBLIC_KEY_FILE = global_settings['public_key_file']
SERVER_PRIVATE_KEY_FILE = global_settings['private_key_file']
SERVER_IDENTITY = global_settings['identity']
CA_KEY = global_settings['CA_key_file']
CA_CRT = global_settings['CA_cert_file']

# In ths implementation there's no mechanism to stop the server accepting new registrations
# but this could be added in the future
server_active = True

application = Flask(__name__)
logging.info("Server Started: Server ID: {}".format(SERVER_IDENTITY))


# This route is for the initial query to check the server is accepting new registrations
# The device sends a simple unadorned GET to the status url – and we'll return a simple JSON object
# with two keys – active & identity. The active key is boolean (denoting if we're active or not); and identity contains
# the server's identity...
@application.route('/KeyEx/register/status', methods=['GET'])
def status():
    return_data = {'active': server_active, 'identity': SERVER_IDENTITY}
    rv = KeyExReturn.OK(json.dumps(return_data))
    return rv()


# Now the route for the actual registration operation
# This one requires a slightly more complex request from the client device. The device must POST a JSON object
# containing its own identity (in a key called 'identity'), it's public key ('key') and the device type ('type')
# Note that in this version of the server the type isn't used for anything – but this is reserved for future use.
# For now any string is valid – and it's written into the database as a free-text string.
# Note that as the device is sending us JSON – the device request needs to have a header of
# {'Content-Type': 'application/json'}
# We'll return HTTP 201 if the request was validated – and HTTP 400 for anything else (e.g. a duplicated request to
# register the same device identity.
@application.route('/KeyEx/register/register', methods=['POST'])
def register():
    registration_data = request.get_json()
    if KeyEx_helpers.check_valid_json(registration_data):
        # Having checked the validity we can safely access the JSON data by key name...
        identity = registration_data['identity']
        pub_key = registration_data['key']
        dev_type = registration_data['type']

        if server_active:
            # The store_data function will check the device doesn't already exist, and then create a record for it,
            # and store it's key & type...
            # it will return false if there's an error – and the error type will be in error...
            db_ret = database_functions.store_data(DATABASE_FILE, identity, pub_key, dev_type)

            if db_ret.success():
                if db_ret.type() == "Success":
                    # All is good – so return the broker details, and the server's public key...
                    key = KeyEx_helpers.keyfile(SERVER_PUBLIC_KEY_FILE)
                    return_data = {'broker': MQTT_BROKER, 'key': key}
                    rv = KeyExReturn.Success(json.dumps(return_data))
                    logging.info("Device {} added.".format(identity))
                    return rv()
                else:
                    # If we get here - something went wrong: as we'll've returned True in success
                    # but have the wrong return type...
                    # This is another one of the "can't happen" errors unless we've screwed up.
                    logging.error("Database return type invalid... {}".format(db_ret.message()))
                    return KeyExReturn.DatabaseError("Internal Error")()

            else:
                # We couldn't add the data to the database... So let's find out why...
                if db_ret.type() == 'NonUnique':
                    # Most likely is that we're trying to add a Device ID we already have...
                    rv = KeyExReturn.NonUniqueKey(identity)
                    logging.warning(rv.message())
                    return rv()

                elif db_ret.type() == 'NotConnected':
                    # We couldn't connect to the database...
                    # This is the worst case: so log as an error...
                    logging.error("Could not connect to the database... {}".format(db_ret.message()))
                    # Since this can't be caused by the user; there's nothing to report back beyond the generic message
                    return KeyExReturn.DatabaseConnectionError()()

                else:
                    # Something else went wrong with the database - so we'll return a generic database error
                    # This has a status value of 500...
                    # Together with any message from the database (this should never happen).

                    return KeyExReturn.DatabaseError(db_ret.message())()
        else:
            # if server is inactive...
            # Note: the odd syntax here is because we initialize and then call the KeyExReturn.Forbidden object
            logging.warning("Device registration from {}, attempted when server was inactive.".format(identity))
            return KeyExReturn.Forbidden()()
    else:
        # if invalid JSON...
        # We'll generate a list of the missing keys...
        missing = KeyEx_helpers.missing_json(registration_data)

        # ...and log that list as a warning.
        logging.warning("JSON data received had missing values: {}".format(missing))

        # We'll also create a dictionary we can return showing the missing values.
        processed_data = {}
        for d in missing:
            processed_data.update({d: ''})

        # Again we'll use the custom class - with the same syntax as the Forbidden case...
        return KeyExReturn.MissingJSON(processed_data)()


# Lastly we'll add an end-point to let us test the key that we have got from the device – and let the device
# test the key we have sent to it...
# The device is expected to send a JSON object containing two keys: it's own identity ('identity') and a signature
# ('signature') – created using the device's private key. We will then check this using the device public key we have on
# file; and if it is valid we will respond with another JSON object in the same format: but with the signature derived
# using our own private key. The device can then check this with the public key it (should have) already received in the
# registration step
@application.route('/KeyEx/register/validate', methods=['POST'])
def validate():
    validation_data = request.get_json()
    identity = validation_data['identity']
    # Because the signatures are composed of arbitrary byte-streams we need to base64 encode them before trying to put
    # them into a JSON object - and so we must reverse that process here...
    signature = base64.decodebytes(validation_data['signature'].encode())

    # Next we need to get the key string associated with the public key for the device that's claiming to have the
    # specified identity...
    key_string = database_functions.get_key(DATABASE_FILE, identity)

    # ...and we need to restore the key to the full PEM format that the RSA functions are expecting.
    restored_key = KeyEx_helpers.fixkey(key_string)

    # Now we can import that restored key string into a full RSA key object, get the SAH256 hash for the
    # message (the device ID), and create a verifier object to check the signature...
    pbkey = serialization.load_pem_public_key(restored_key.encode(), backend=default_backend())

    # If the verifier passes the device key we have is a valid public key for the private key that the device is using
    try:
        pbkey.verify(signature, identity.encode(),
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())

        # If we get here without throwing an exception then the signature was valid: so we'll return our own identity,
        # signed with our private key
        with open(SERVER_PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

        signature = private_key.sign(SERVER_IDENTITY.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                 salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        # Note that as before - we must use base64 encoding before we can serialize this into JSON.
        return_data = {'identity': SERVER_IDENTITY, 'signature': base64.encodebytes(signature).decode()}

        # Lastly we return the data, with a HTTP 200
        rv = KeyExReturn.OK(json.dumps(return_data))
        return rv()

    # If we threw an exception then the key didn't validate - so we must return a signature validation error (HTTP 400)
    except (InvalidSignature, ValueError, TypeError) as e:
        rv = KeyExReturn.SignatureVerificationError()
        return rv()


@application.route('/KeyEx/register/access', methods=['POST'])
def access_keys():
    access_key_data = request.get_json()
    identity = access_key_data['identity']
    csr_data = base64.decodebytes(access_key_data['csr'].encode())
    signature = base64.decodebytes(access_key_data['signature'].encode())

    key_string = database_functions.get_key(DATABASE_FILE, identity)

    # ...and we need to restore the key to the full PEM format that the RSA functions are expecting.
    restored_key = KeyEx_helpers.fixkey(key_string)

    # Now we can import that restored key string into a full RSA key object, get the SAH256 hash for the
    # message (the device ID), and create a verifier object to check the signature...
    pbkey = serialization.load_pem_public_key(restored_key.encode(), backend=default_backend())

    # Validate that the signature is valid for the csr_data signed by this device...
    try:
        pbkey.verify(signature, csr_data,
                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                     hashes.SHA256())

        # We're okay – so sign it...
        with open(CA_KEY, 'rb') as f:
            ca_key_data = f.read()
        ca_key = serialization.load_pem_private_key(ca_key_data, b'rabbit', default_backend())

        csr = x509.load_pem_x509_csr(csr_data, default_backend())

        with open(CA_CRT, 'rb') as f:
            ca_crt_data = f.read()
        ca_crt = x509.load_pem_x509_certificate(ca_crt_data, default_backend())

        if isinstance(csr.signature_hash_algorithm, hashes.SHA256):
            cert = x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_crt.issuer).public_key\
                (csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before\
                (datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
                .sign(ca_key, hashes.SHA256(), default_backend())

            return_data = {'certificate': base64.encodebytes(cert.public_bytes(serialization.Encoding.PEM)).decode(),
                           'CA_certificate': base64.encodebytes(ca_crt_data).decode()}

            rv = KeyExReturn.OK(json.dumps(return_data))
            return rv()

    except (InvalidSignature, ValueError, TypeError) as e:
        rv = KeyExReturn.CSRVerificationError()
        return rv()


@application.route('/KeyEx/register/get_key/<identity>', methods=['GET'])
def get_pub_key(identity):
    # Given that we only need to pass one value – we won't use JSON – but rather use a simple
    # argument...e.g. .../get_key/a3ca9020-b2dc-4d4d-bbf9-42320c7730a0

    # Get the key - if we have it...
    key_string = database_functions.get_key(DATABASE_FILE, identity)

    if key_string is None:
        # We don't have a key for this identity...
        rv = KeyExReturn.IDNotFound()

    else:
        # We have the key - so now we need to restore the key to the full PEM format
        # that RSA functions will expecting...
        restored_key = KeyEx_helpers.fixkey(key_string)

        # And to return this complete key to the C2 server we need to first Base64 encode it.
        encoded_key = base64.encodebytes(restored_key.encode())
        rv = KeyExReturn.OK(encoded_key)

    return rv()


# All of the end-points are specified now –so lastly le is add a custom error handler for the 400 status code
# which we will use to catch malformed JSON; and use our normal approach to return the data.
@application.errorhandler(400)
def handle_bad_json(error):
    logging.warning("Malformed JSON data received")
    return KeyExReturn.BadJSON(error.description)()


if __name__ == '__main__':
    application.run()
