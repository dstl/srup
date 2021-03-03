# "Device" client for key exchange server integration...

import requests
import CryptoFunctions
import json
import uuid
import base64
import logging
import configparser

# The process for key exchange from the client's perspective is that we will first check to see if the server is
# actively accepting registration requests, then (assuming it is) to make the exchange; and then to validate the
# key exchange has worked by exchanging signed messages.

# If we're using an encrypted connection to the MQTT broker – then we then also need to generate an access key...
# and a CSR to go with it: with the COMMON NAME set to the identity of the device – and send it, along with a signature
# for the CSR generated using the original (identity) key, to teh server...
# If everything matches at the other end, the server will issue a certificate signed using a access key CA
# (also used by the broker) and sends this to the device. This access key & the associated certificate will then be
# used when connecting to the broker...


# So we start with a function to get the status of the server...
# We send a simple GET to the server address, and expect to receive a HTTP 200 code – along with a JSON object
# containing the server's identity ('identity') – and it's status ('active').
# If all is good, we'll return the server identity, and active and valid will both be true...
# If the server is inactive (but doesn't return an error) then active is false, but valid is true
# If we get an error - then active & valid will be false.
def _get_status(url, base_url, chain=None):
    server_info = {'identity': None, 'active': False, 'valid': False}
    if chain is not None:
        r = requests.get(url, verify=chain)
    else:
        r = requests.get(url)

    if r.status_code == 200:
        rv = r.json()
        if rv['active']:
            logging.debug("Server {} is active, with identity: {}".format(base_url, rv['identity']))
            server_info['identity'] = rv['identity']
            server_info['active'] = True
            server_info['valid'] = True
        else:
            logging.error("KeyEx Server at {} is inactive.".format(base_url))
            server_info['valid'] = True
    else:
        logging.error("KeyEx Server {} error code {}.".format(base_url, r.status_code))
    return server_info


# Next we have a function for the actual registration operation...
# This one is pretty straight forward. We send a POST with the JSON object consisting of our (device) identity,
# a copy of our public key, and the device type...
# We also require a device type to be specified – although this is optionally specified by the user.
# If not specified then it should be None; but we'll be type safe here - just in case.

def _registration(url, identity, dev_type, key_file, chain=None):
    if dev_type is not None and isinstance(dev_type, str):
        device_type = dev_type
    else:
        device_type = "default"
    data = {'identity': identity, 'key': CryptoFunctions.get_key_from_file(key_file), 'type': device_type}
    headers = {'Content-Type': 'application/json'}
    if chain is not None:
        r = requests.post(url, data=json.dumps(data), headers=headers, verify=chain)
    else:
        r = requests.post(url, data=json.dumps(data), headers=headers)
    if r.status_code == 201:
        return r.status_code, r.json()['broker'], r.json()['default_c2'], r.json()['key'], r.content
    else:
        return r.status_code, None, None, None, r.content


# The next function here – is one for the validation operation...
# We'll start by sending a JSON object consisting of the device identity, and a signature based on our private key...
def _validation(url, identity, key_file, encoded_server_public_key, chain=None):
    signature = CryptoFunctions.sign(identity, key_file)

    # We need to also send a suitable header to indicate that we're sending JSON...
    headers = {'Content-Type': 'application/json'}

    # And note that we must use base64 encoding for the signature – since it is composed from an arbitrary bytestream
    # when we receive the signature from the server we must reverse this process...
    data = {'identity': identity, 'signature': base64.encodebytes(signature).decode()}
    if chain is not None:
        r = requests.post(url, data=json.dumps(data), headers=headers, verify=chain)
    else:
        r = requests.post(url, data=json.dumps(data), headers=headers)

    # Having POSTed that – we're expecting HTTP 200 – and if we don't get it – then we'll return False as something has
    # clearly already gone wrong...
    if r.status_code == 200:
        #
        # Given that we're no-longer using the validation check on the reply; we just return True if we get here...
        # # If we do have HTTP 200 – then we need to try to verify the signature we've received against the public
        # # key we have already, corresponding to the server – and we simple return the outcome of that verification
        # # step.
        # return CryptoFunctions.verify(message=r.json()['identity'],
        #                               signature=base64.decodebytes(r.json()['signature'].encode()),
        #                               key=CryptoFunctions.load_public_key_from_base64_string(
        #                                                                                 encoded_server_public_key))
        return True
    else:
        return False


# Now we have the function to provide the access_key certificate exchange...
def _access_keys(url, identity, key_file, csr_file, crt_file, ca_crt_file, chain=None):
    csr = CryptoFunctions.load_csr(csr_file)

    # Note the signature is only based on the CSR data - not the identity...
    # We send the identity only to enable the server to identify who we are.
    signature = CryptoFunctions.sign(CryptoFunctions.get_csr_bytes(csr), key_file)

    # We need to also send a suitable header to indicate that we're sending JSON...
    headers = {'Content-Type': 'application/json'}

    # And note that we must use base64 encoding for the signature – since it is composed from an arbitrary bytestream
    # when we receive the signature from the server we must reverse this process...
    data = {'csr': base64.encodebytes(CryptoFunctions.get_csr_bytes(csr)).decode(), 'identity': identity,
            'signature': base64.encodebytes(signature).decode()}

    if chain is not None:
        r = requests.post(url, data=json.dumps(data), headers=headers, verify=chain)
    else:
        r = requests.post(url, data=json.dumps(data), headers=headers)
    if r.status_code == 200:
        # If we do have HTTP 200 – then we need to write the data we have to files...
        with open(crt_file, 'wb') as f:
            f.write(base64.decodebytes(r.json()['certificate'].encode()))

        with open(ca_crt_file, 'wb') as f:
            f.write(base64.decodebytes(r.json()['CA_certificate'].encode()))
        return True
    else:
        return False


# Now the main function we'll call...
# Here note that although a device_type must be specified, the actual specification of a value for this is optional
# The value defaults to None if a specific type is not specified.
def KeyEx(config_filename, base_url, chain, device_type, syndication=False):
    status_part = "/KeyEx/register/status"
    registration_part = "/KeyEx/register/register"
    validation_part = "/KeyEx/register/validate"
    access_key_part = "/KeyEx/register/access"

    # We'll generate filenames once we have our ID…
    CONFIG_FILE = config_filename
    port = None

    # Lines enabling local testing...
    # port = 5000

    if port is not None:
        status_url = base_url + ":" + str(port) + status_part
        registration_url = base_url + ":" + str(port) + registration_part
        validation_url = base_url + ":" + str(port) + validation_part
        access_key_url = base_url + ":" + str(port) + access_key_part
    else:
        status_url = base_url + status_part
        registration_url = base_url + registration_part
        validation_url = base_url + validation_part
        access_key_url = base_url + access_key_part
    logging.info(status_url)

    # The original plan was to specify a device ID – but actually it makes much more sense to generate one every time
    # we need it, i.e. every time we run the registration process...
    # We need a 64-bit integer encoded as a hex string – so we'll use a half-UUID (taking the first 64-bit for better
    # uniqueness
    device_ID = hex(uuid.uuid4().int >> 64)[2:]
    logging.info("Device ID {} allocated.".format(device_ID))

    short_name = "{:08X}".format(CryptoFunctions.fletcher32(device_ID, len(device_ID)))
    logging.info("Short name for Device ID {} is {}.".format(device_ID, short_name))

    public_key_file = "{}.pub".format(short_name)
    private_key_file = "{}.prv".format(short_name)

    remote_keys = {}
    # server_key_file = "server.pem"

    access_key_file = "{}.key".format(short_name)
    access_csr_file = "{}.csr".format(short_name)
    access_crt_file = "{}.crt".format(short_name)
    access_ca_crt_file = "{}.ca".format(short_name)

    # Now setup a config file parser – so we can write the config out to a file...
    config = configparser.ConfigParser()

    logging.info('Generating Public / Private Key Pair')
    logging.info('Private Key File: {}; Public Key File: {}'.format(private_key_file, public_key_file))
    # We're ready to go - so first we must create our own key pair
    CryptoFunctions.generate_keys(private_key_file, public_key_file)

    logging.info("Key-pair for Device ID {} generated.".format(device_ID))
    logging.info("Attempting to connect to {}".format(base_url))
    if chain is not None:
        logging.info("Using Server certificate chain {}".format(chain))
    try:
        status = _get_status(status_url, base_url, chain=chain)

        # Next we'll check the status of the key server; and if it's active we'll extract the key
        # from the public key file...
        if status['valid']:
            device_public_key = CryptoFunctions.load_public_key(public_key_file)

            # If we were successful in getting the key from the file, we will now call the registration function
            # passing in the url, key, and our device ID - and getting the HTTP code & response – along with
            # the broker address, default C2 server ID & server's public key if everything is okay...
            # Note that the broker URL and the default server ID are plain-text strings; and the server's key is a
            # base64 encoded byte-stream...
            if syndication:
                device_type = 'RSYND'
                
            if device_public_key is not None:
                code, broker, server_id, server_key, response = _registration(registration_url, device_ID, device_type,
                                                                              public_key_file, chain=chain)

                # If we get back a response code of HTTP 201 ("CREATED") - then we'll continue
                if code == 201:
                    logging.info("Received broker address: {}".format(broker))

                    # Next we'll get the public key for the server...
                    remote_keys[server_id] = server_key

                    # TODO: TIDY THIS!
                    # We no-longer want to store the public_key in a file – as we're using the stringified version
                    # in the config file – so we'll skip this part...
                    #
                    # CryptoFunctions.write_public_key_to_file(server_key, server_key_file)

                    # Lastly we'll call the validation url – to make sure that the keys we have
                    # (and which the server has) are actually two valid pairs...

                    if _validation(validation_url, device_ID, private_key_file, server_key, chain=chain):
                        logging.info("Key Validation Successful")

                        # Lastly we now need to generate and exchange the access keys / CSR / certificate for MQTT
                        CryptoFunctions.generate_access_key(access_key_file)
                        CryptoFunctions.generate_csr(access_csr_file, access_key_file, device_ID)

                        if _access_keys(access_key_url, device_ID, private_key_file, access_csr_file,
                                        access_crt_file, access_ca_crt_file, chain=chain):

                            logging.info("Certificate Received")

                            # If we made it through okay; then we'll write the config file...
                            if not syndication:
                                config['Device'] = {'Identity': device_ID,
                                                    'registration_url': base_url,
                                                    'short_name': short_name}

                                config['SRUP'] = {'Broker': broker,
                                                  'Server_Identity': server_id,
                                                  'Chain': (chain if chain is not None else "")}

                                config['Keys'] = {'local_public': public_key_file,
                                                  'local_private': private_key_file,
                                                  'remote_keys': remote_keys}

                                config['Access'] = {'key': access_key_file,
                                                    'certificate': access_crt_file,
                                                    'ca_certificate': access_ca_crt_file}
                            else:
                                config['Syndication'] = {'identity': device_ID,
                                                         'registration_url': base_url,
                                                         'Broker': broker,
                                                         'ca_cert': access_ca_crt_file,
                                                         'cert': access_crt_file,
                                                         'key': access_key_file,
                                                         'syndication_public': public_key_file,
                                                         'syndication_private': private_key_file,
                                                         'server_identity': server_id}
                                #                        'chain': (chain if chain is not None else "")

                            try:
                                with open(config_filename, 'w') as configfile:
                                    config.write(configfile)

                            except IOError as iox:
                                logging.error(iox)

                            logging.info("Key Exchange Complete")

                        else:
                            logging.error("Access Certificate Failure")
                    else:
                        # Validation fail...
                        logging.error("Validation Failure")

                # If we didn't get HTTP 201 – a record for the device wasn't created; so something went wrong...
                else:

                    # For now we'll print the code & response text - but we would want to use a
                    # logger in due course to do this properly.
                    logging.error("Server Error. Error Code {}".format(code))
                    logging.error("{}".format(response.decode()))

            # If something went wrong with the key extraction from our own public key file
            else:
                logging.error("Key Extraction from {} failed.".format(public_key_file))

    # Lastly we have the situation where something went wrong with the requests library –
    # most likely this means that the server is not online.
    except IOError:
        logging.error("Key Server {} could not be reached.".format(base_url))


def _c2_check(base_url, chain, server_id):
    check_part = "/KeyEx/register/c2_check/"
    url = base_url + check_part + server_id

    if chain is not None:
        return requests.get(url, verify=chain)
    else:
        return requests.get(url)


def _c2_register(base_url, chain, server_id, server_key, server_token):
    register_part = "/KeyEx/register/c2/"
    url = base_url + register_part

    data = {'identity': server_id, 'key': server_key, 'signature': server_token}
    headers = {'Content-Type': 'application/json'}

    if chain is not None:
        r = requests.post(url, data=json.dumps(data), headers=headers, verify=chain)
    else:
        r = requests.post(url, data=json.dumps(data), headers=headers)

    if r.status_code == 201:
        return True  # We're done
    else:
        # Something went wrong – so log it, and we'll bail out.
        if r.status_code == 400:
            logging.error("Signature Validation Failed - {}".format(r))
            return False
        elif r.status_code == 500:
            logging.error("Database error...")
            return False
        logging.error("Fatal Error")  # We shouldn't ever be able to get here...
        return False


def KeyEx_C2(base_url, chain, server_id, server_key_file, server_token_file):
    rv = _c2_check(base_url, chain, server_id)

    if rv.status_code == 200:
        # The server already has our ID - so nothing to do...
        return True

    elif rv.status_code == 404:
        # We're a new server to this KeyEx service - so send our credentials and key...
        logging.info("Registering new C2 server identity with KeyEx service at {}".format(base_url))
        with open(server_token_file, 'r') as f:
            server_token = f.read()
        server_key = CryptoFunctions.get_key_from_file(server_key_file)
        return _c2_register(base_url, chain, server_id, server_key, server_token)

    elif rv.status_code == 400:
        # We'll get a 400 error code if the server ID we're using, is not valid for a server...
        # This shouldn't ever happen if everything is working okay.
        logging.error("Server ID is invalid for a server {}".format(server_id))
        return False
    else:
        # Something is very wrong! We have an unexpected HTTP code...
        logging.error("KeyEx server registration check failed - error {}".format(rv))
        return False
