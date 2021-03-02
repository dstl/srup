# CryptoFunctions – provides a tidy wrapper for the cryptography library functions...
# Note that we're now using the cryptography library, rather than Cryptodome (which is a little neater) because we
# want to use a single crypto library for everything, and Cryptodome doesn't support the X509 operations we need to
#  support the issuance of CSRs and certificates...
# See: https://cryptography.io/en/latest/ for documentation.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidKey
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import logging

public_key_header = '-----BEGIN PUBLIC KEY-----'
public_key_footer = '-----END PUBLIC KEY-----'


# First off we have a simple function which will generate an RSA PEM key-pair for us
def generate_keys(pv_file, pb_file):
    logging.info("generate_keys")
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        logging.info("Private Key Generated")
        public_key = private_key.public_key()
        logging.info("Public Key Extracted")
        # Write the keys to files...
        with open(pv_file, 'wb') as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                              encryption_algorithm=serialization.NoEncryption(),
                                              format=serialization.PrivateFormat.TraditionalOpenSSL))

        with open(pb_file, 'wb') as f:
            f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        return True

    except IOError as e:
        logging.error("IO Error - {}".format(e))
        return False

    except ValueError as e:
        logging.error("Value Error - {}".format(e))
        return False


def load_private_key(filename):
    try:
        with open(filename, "rb") as key_file:
            loaded_private_key = serialization.load_pem_private_key(key_file.read(), password=None,
                                                                    backend=default_backend())
            return loaded_private_key

    except IOError:
        return None

    except InvalidKey:
        return None


def load_public_key(filename):
    try:
        with open(filename, "rb") as key_file:
            loaded_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            return loaded_public_key

    except IOError:
        return None

    except InvalidKey:
        return None


# These next two functions are used to get or set the key for / from the JSON we send over the web...

# This will extract the key (in PEM format) from the PEM keyfile...
# (Essentially we just strip off the header and footer).
def get_key_from_file(filename):
    # This will return the key string from a file...
    key = ''
    with open(filename, 'r') as f:
        for line in f:
            if line[0:5] != "-----":
                key += line[:-1]
    if len(key) > 0:
        return key
    else:
        return None


# This is the counterpart to the previous function – in that it creates a public key PEM file
# for a raw PEM format key string
def write_public_key_to_file(key, filename):
    with open(filename, "w") as key_file:
        print("{}".format(public_key_header), file=key_file)
        counter = 0
        body = ""
        for char in key:
            body += char
            counter += 1
            if counter == 64:
                body += '\n'
                counter = 0

        print("{}".format(body), file=key_file)
        print("{}".format(public_key_footer), file=key_file)


# Next we need a function to return the base64 encoded string version of the (remote) public-key...
def get_base64_public_key_string(key):
    key = public_key_header + '\n' + key + '\n' + public_key_footer
    return base64.encodebytes(key.encode())


# We also need the reverse...
def load_public_key_from_base64_string(encoded_key_string):
    decoded_key_bytes = base64.decodebytes(encoded_key_string)
    public_key = serialization.load_pem_public_key(decoded_key_bytes, backend=default_backend())
    return public_key


# Here is a simple implementation of a 32-bit Fletcher's Checksum – which we'll use to generate
# filenames for key & certificate files from the device ID...
# A simple implementation of a 32-bit Fletcher checksum...
def fletcher32(data, length):
    w_len = length
    c0 = 0
    c1 = 0
    x = 0

    while w_len >= 360:
        for i in range(360):
            c0 = c0 + ord(data[x])
            c1 = c1 + c0
            x = x + 1
        c0 = c0 % 65535
        c1 = c1 % 65535
        w_len = w_len - 360

    for i in range(w_len):
        c0 = c0 + ord(data[x])
        c1 = c1 + c0
        x = x + 1
    c0 = c0 % 65535
    c1 = c1 % 65535
    return c1 << 16 | c0


# Next up a special function to get the CSR data from the CSR object...
def get_csr_bytes(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


# The sign function rather does what it says on the tin – we sign the message using the key file
# specified and return the signature as a bytestream
def sign(message, key_file):
    loaded_private_key = load_private_key(key_file)
    if loaded_private_key is not None:
        if not isinstance(message, bytes):
            message = message.encode()
        signature = loaded_private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                 salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature
    else:
        return None


# Unsurprisingly verify provides a counterpart to sign – in order to verify a signature that we provide, along with the
# message that was (allegedly) signed, and the public key corresponding to the private key (allegedly) used to
# sign it... We return a boolean value – based on whether or not the verification is successful.
# Note that here (unlike above) we pass a key object - not a key_file...
def verify(message, signature, key):
    try:
        key.verify(signature, message.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True

    except InvalidSignature:
        return False


# Now we have some functions to do the X509 stuff...
# First we generate another key-pair file
def generate_access_key(access_key_file):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Write the key to a file...
    with open(access_key_file, 'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.NoEncryption()))


def generate_csr(access_csr_file, access_key_file, device_ID):
    with open(access_key_file, 'rb') as f:
        data = f.read()

    key = serialization.load_pem_private_key(data, password=None, backend=default_backend())

    csr_name = []
    csr_name.append(x509.NameAttribute(NameOID.COUNTRY_NAME, u'UK'))
    csr_name.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'UNK'))
    csr_name.append(x509.NameAttribute(NameOID.LOCALITY_NAME, u'UNK'))
    csr_name.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SRUP_DEVICE'))
    csr_name.append(x509.NameAttribute(NameOID.COMMON_NAME, str(device_ID)))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(csr_name)).sign(key, hashes.SHA256(),
                                                                                         default_backend())

    with open(access_csr_file, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def load_csr(filename):
    try:
        with open(filename, "rb") as csr_file:
            csr_data = csr_file.read()

        csr = x509.load_pem_x509_csr(csr_data, default_backend())
        return csr

    except IOError:
        return None

    except InvalidKey:
        return None


# Lastly here, we have a function that essentially does the same thing as  write_public_key_to_file() – the difference
# being that this one doesn't write to a file – but rather just returns a string, containing the adorned key string.
def recreate_public_key(k):
    kk = '-----BEGIN PUBLIC KEY-----\n'
    body = ""
    counter = 0
    for char in k:
        body += char
        counter += 1
        if counter == 64:
            body += '\n'
            counter = 0
    return kk + body + '\n-----END PUBLIC KEY-----'
