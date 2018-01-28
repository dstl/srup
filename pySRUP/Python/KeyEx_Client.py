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
def get_status(url, base_url):
    server_info = {'identity': None, 'active': False, 'valid': False}
    r = requests.get(url)
    if r.status_code == 200:
        rv = r.json()
        if rv['active']:
            logging.debug("Server {} is active, with identity: {}".format(base_url, rv['identity']))
            server_info['identity'] = rv['identity']
            server_info['active'] = True
            server_info['valid'] = True
        else:
            logging.error("Key Server at {} is inactive.".format(base_url))
            server_info['valid'] = True
    else:
        logging.error("Key Server {} error code {}.".format(base_url, r.status_code))
    return server_info


# Next we have a function for the actual registration operation...
# This one is pretty straight forward. We send a POST with the JSON object consisting of our (device) identity,
# a copy of our public key, and the device type... Here that's hard-coded to TEST – since we're not yet using this
# capability
def registration(url, identity, key_file):
    data = {'identity': identity, 'key': CryptoFunctions.get_key_from_file(key_file), 'type': 'TEST'}
    headers = {'Content-Type': 'application/json'}
    r = requests.post(url, data=json.dumps(data), headers=headers)
    if r.status_code == 201:
        return r.status_code, r.json()['broker'], r.json()['key'], r.content
    else:
        return r.status_code, None, None, r.content


# The next function here – is one for the validation operation...
# We'll start by sending a JSON object consisting of the device identity, and a signature based on our private key...
def validation(url, identity, key_file, server_public_key_file):
    signature = CryptoFunctions.sign(identity, key_file)

    # We need to also send a suitable header to indicate that we're sending JSON...
    headers = {'Content-Type': 'application/json'}

    # And note that we must use base64 encoding for the signature – since it is composed from an arbitrary bytestream
    # when we recieve the signature from the server we must reverse this process...
    data = {'identity': identity, 'signature': base64.encodebytes(signature).decode()}
    r = requests.post(url, data=json.dumps(data), headers=headers)

    # Having POSTed that – we're expecting HTTP 200 – and if we don't get it – then we'll return False as something has
    # clearly already gone wrong...
    if r.status_code == 200:
        # If we do have HTTP 200 – then we need to try to verify the signature we've received against the public key we
        # have already, corresponding to the server – and we simple return the outcome of that verification step.
        return CryptoFunctions.verify(message=r.json()['identity'],
                                      signature=base64.decodebytes(r.json()['signature'].encode()),
                                      key=CryptoFunctions.load_public_key(server_public_key_file))
    else:
        return False


# Now we have the function to provide the access_key certificate exchange...
def access_keys(url, identity, key_file, csr_file, crt_file, ca_crt_file):
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


# Now the main function we'll call
def KeyEx(config_filename, base_url):
    status_part = "/KeyEx/register/status"
    registration_part = "/KeyEx/register/register"
    validation_part = "/KeyEx/register/validate"
    access_key_part = "/KeyEx/register/access"

    public_key_file = "public.pem"
    private_key_file = "private.pem"
    server_key_file = "server.pem"

    access_key_file = "device.key"
    access_csr_file = "device.csr"
    access_crt_file = "device.crt"
    access_ca_crt_file = "ca.crt"

    LOG_FILE = "KeyEx-Client.log"

    CONFIG_FILE = config_filename
    port = None

    # Lines enabling local testing...
    # port = 5000
    # base_url  = "http://localhost"

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

    # The original plan was to specify a device ID – but actually it makes much more sense to generate one every time
    # we need it, i.e. every time we run the registration process...
    # We need a 64-bit integer encoded as a hex string – so we'll use a half-UUID (taking the first 64-bit for better
    # uniqueness
    device_ID = hex(uuid.uuid4().int >> 64)[2:]

    # Next up the logging...
    # In production we'll expect this to be a headless device – so there's no point logging to stdout / stderr
    # So we'll just log to a file.
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t\t%(message)s')
    logfile = logging.FileHandler(LOG_FILE)
    logfile.setLevel(logging.INFO)
    logfile.setFormatter(formatter)
    logger.addHandler(logfile)

    # Now setup a config file parser – so we can write the config out to a file...
    config = configparser.ConfigParser()

    # We're ready to go - so first we must create our own key pair
    CryptoFunctions.generate_keys(private_key_file, public_key_file)

    logging.info("Device ID {} generated.".format(device_ID))
    logging.info("Attempting to connect to {}".format(base_url))
    try:
        status = get_status(status_url, base_url)

        # Next we'll check the status of the key server; and if it's active we'll extract the key
        # from the public key file...
        if status['valid']:
            device_public_key = CryptoFunctions.load_public_key(public_key_file)

            # If we were successful in getting the key from the file, we will now call the registration function
            # passing in the url, key, and device ID - and getting the HTTP code & response – along with
            # the broker address & server's public key if everything is okay...
            if device_public_key is not None:
                code, broker, server_key, response = registration(registration_url, device_ID, public_key_file)

                # If we get back a response code of HTTP 201 ("CREATED") - then we'll continue
                if code == 201:
                    logging.debug("Received broker address: {}".format(broker))

                    # Next we'll write the server's key to a suitable PEM file
                    CryptoFunctions.write_public_key_to_file(server_key, server_key_file)

                    # Lastly we'll call the validation url – to make sure that the keys we have
                    #  (and which the server has) are actually two valid pairs...
                    if validation(validation_url, device_ID, private_key_file, server_key_file):

                        # For now as this is just a demo – we'll simply print the outcome of the process...
                        logging.info("Key Validation Successful")

                        # Lastly we now need to generate and exchange the access keys / CSR / certificate
                        CryptoFunctions.generate_access_key(access_key_file)
                        CryptoFunctions.generate_csr(access_csr_file, access_key_file, device_ID)

                        if access_keys(access_key_url, device_ID, private_key_file, access_csr_file,
                                       access_crt_file, access_ca_crt_file):

                            logging.info("Certificate Received")

                            # If we made it through okay; then we'll write the config file...

                            config['Device'] = {'Identity': device_ID,
                                                'registration_url': base_url}

                            config['SRUP'] = {'Broker': broker,
                                              'Server_Identity': status['identity']}

                            config['Keys'] = {'device_public': public_key_file,
                                              'device_private': private_key_file,
                                              'server': server_key_file}
                            config['Access'] = {'key': access_key_file,
                                                'certificate': access_crt_file,
                                                'ca_certificate': access_ca_crt_file}

                            with open(CONFIG_FILE, 'w') as configfile:
                                config.write(configfile)

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