#!/usr/local/bin/python3
# This is a simple (?) script to generate all of the requisite keys that are required
# to bootstrap a new SRUP backend setup.

import argparse
import sys
import datetime
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

DEFAULT_ISSUER = "SRUP Backend"
DEFAULT_COUNTRY = "GB"
__version__ = "1.0"
__prog__ = "keygen"

# First off we have a couple of helper functions to generate keypairs, etc.
# We'll call these from the main generator functions...


def _print_gen_ok(name):
    q = len(name)
    padding = "." * (31 - q)
    print("{}  {}  OK".format(name, padding))


def _print_header(text, first=False):
    q = len(text)
    ruler = "-" * q
    if not first:
        print("\n")
    print("{}\n{}\n".format(text, ruler))


def _generate_keypair(path, pv, pb=None):
    try:

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        # Write the key to a file...
        with open(path + '/' + pv, 'wb') as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                              encryption_algorithm=serialization.NoEncryption(),
                                              format=serialization.PrivateFormat.TraditionalOpenSSL))
        if pb is not None:
            public_key = private_key.public_key()
            with open(path + '/' + pb, 'wb') as f:
                f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        return private_key

    except IOError as e:
        print("IO Error\t{}".format(e))
        return None

    except ValueError as e:
        print("Value Error\t{}".format(e))
        return None


def _generate_cert(path, cert_file, key, signing_key, common_name, issuer=None, is_ca=False,
                   url=None, issuer_cert=None, fullchain=False, country_name=None):

    if fullchain:
        if issuer_cert is None:
            return None

    one_day = datetime.timedelta(1, 0, 0)
    if is_ca:
        duration = 1825
    else:
        duration = 365

    try:

        if issuer is None:
            issuer = DEFAULT_ISSUER
        if country_name is None:
            country_name = DEFAULT_COUNTRY

        if common_name is None:
            common_name = url
            url = None

        builder = x509.CertificateBuilder()
        name = [x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

        builder = builder.subject_name(x509.Name(name))

        if issuer_cert is None:
            builder = builder.issuer_name(x509.Name(name))
        else:
            builder = builder.issuer_name(issuer_cert.subject)

        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * duration))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(key.public_key())

        if url is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(url)]), critical=False)

        if is_ca:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)

        certificate = builder.sign(private_key=signing_key, algorithm=hashes.SHA256(), backend=default_backend())

        # Write the cert to file...
        with open(path + '/' + cert_file, 'wb') as f:
            if fullchain:
                f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
                f.write(issuer_cert.public_bytes(encoding=serialization.Encoding.PEM))
            else:
                f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

        return certificate
    except IOError as e:
        print("IO Error\t{}".format(e))
        return None
    except ValueError:
        print("Value Error\t{}".format(e))
        return None


def _generate_stk(path, c2_pub, c2_tk, keyfile):
    try:
        with open(c2_pub, 'rb') as f:
            c2_pubkey = serialization.load_pem_public_key(f.read(), backend=default_backend())

        with open(keyfile, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    except IOError as e:
        print("IO Error\t{}".format(e))
        return False

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(c2_pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
    keyhash = digest.finalize()

    sig = key.sign(keyhash, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                   utils.Prehashed(hashes.SHA256()))
    try:
        with open(path + '/' + c2_tk, 'wb') as f:
            f.write(base64.b64encode(sig))
    except IOError as e:
        print("IO Error\t{}".format(e))
        return False

    if not args.quiet:
        _print_gen_ok(c2_tk)

    return True


# Generate Server RSA keys
def generate_Server_SRUP_keys(server_path, server_pv_file, server_pb_file, server_token_file, keyex_pv_key):
    if server_path is not None:
        if _generate_keypair(path=server_path, pv=server_pv_file, pb=server_pb_file):
            if not args.quiet:
                _print_gen_ok(server_pv_file)
                _print_gen_ok(server_pb_file)
            if _generate_stk(path=server_path, c2_pub=server_pb_file, c2_tk=server_token_file, keyfile=keyex_pv_key):
                return True
            else:
                return False
        else:
            return False


# Generate an RSA PEM key-pair for the KeyEx server...
def generate_SRUP_keys(keyex_pv_file, keyex_pb_file, path):
    if not args.quiet:
        _print_header("Generating SRUP Keys", True)
    if _generate_keypair(path=path, pv=keyex_pv_file, pb=keyex_pb_file) is not None:
        if not args.quiet:
            _print_gen_ok(keyex_pv_file)
            _print_gen_ok(keyex_pb_file)
            return True
        else:
            return True
    else:
        return False


# Next we have a function which will generate an RSA PEM key-pair for the CA, a CA certificate,
# and a broker key and a certificate signing the broker key with the CA key...
def generate_broker_keys(path, ca_path, ca_key_file, ca_cert_file, broker_key_file, broker_cert_file, issuer=None,
                         url=None, country_name=None):

    if not args.quiet:
        _print_header("Generating Broker Keys & Certificates")

    cakey = _generate_keypair(ca_path, ca_key_file)
    if cakey is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(ca_key_file)

    # Now generate the self-signed CA certificate... self-signed since this is a root CA.
    cacert = _generate_cert(ca_path, ca_cert_file, common_name="SRUP Root CA Key", key=cakey, signing_key=cakey,
                            issuer=issuer, is_ca=True, country_name=country_name)

    if cacert is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(ca_cert_file)

    # Now we create a new keypair for the broker key...
    brokerkey = _generate_keypair(path, broker_key_file)
    if brokerkey is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(broker_key_file)

    # Now we have that, we should use the CA key to generate a certificate for the broker key...
    brokercert = _generate_cert(path, broker_cert_file, common_name=None,
                                signing_key=cakey, key=brokerkey, issuer=issuer, issuer_cert=cacert, url=url,
                                country_name=country_name)

    if brokercert is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(broker_cert_file)

    return True


# Now we'll generate the broker keys for the C2 server...
# Note that in order to be able to do this, we need a few things to have been generated previously
# and passed in to us here to use...
# Specifically the CA key and the CA certificate...
def generate_server_broker_keys(server_path, server_key_file, server_cert_file, ca_file, cacert_file):

    # Load the CA certificate...
    try:
        with open(cacert_file, 'rb') as f:
            cacert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(ca_file, 'rb') as f:
            cakey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    except IOError as e:
        print("IO Error\t{}".format(e))
        return False

    serverkey = _generate_keypair(server_path, server_key_file)
    if serverkey is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(server_key_file)

    attr = cacert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if len(attr) == 1:
        issuer = attr[0].value
    else:
        issuer = DEFAULT_ISSUER

    attr = cacert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if len(attr) == 1:
        country_name = attr[0].value
    else:
        country_name = DEFAULT_COUNTRY

    servercert = _generate_cert(server_path, server_cert_file, common_name="Server",
                                signing_key=cakey, key=serverkey, issuer=issuer, issuer_cert=cacert,
                                country_name=country_name)
    if servercert is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(server_cert_file)


# Lastly, we have a function which will generate an RSA PEM key-pair for the web CA and certificate,
# and create a key & certificate for the webserver.
def generate_webserver_keys(path, web_ca_key_file, web_ca_cert_file, web_key_file, web_cert_file, issuer, url,
                            country_name=None):

    if not args.quiet:
        _print_header("Generating Web Server Keys & Certificates")
    webcakey = _generate_keypair(path, web_ca_key_file)
    if webcakey is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(web_ca_key_file)

    webcacert = _generate_cert(path, web_ca_cert_file, key=webcakey, signing_key=webcakey, issuer=issuer, url=url,
                               common_name="SRUP Web CA", is_ca=True, country_name=country_name)

    if webcacert is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(web_ca_cert_file)

    webkey = _generate_keypair(path, web_key_file)
    if webkey is None:
        return False
    else:
        if not args.quiet:
            _print_gen_ok(web_key_file)

    webcert = _generate_cert(path, web_cert_file, key=webkey, signing_key=webcakey, issuer=issuer, url=url,
                             common_name="localhost", issuer_cert=webcacert, fullchain=True, country_name=country_name)
    if webcert is not None:
        if not args.quiet:
            _print_gen_ok(web_ca_cert_file)
        return True
    else:
        return False

#######################################################################################################################


introtext="SRUP KeyGenTool\n\nThis tool can generate all of the keys that are required to support instances of a SRUP " \
          "system.\nThere are two modes of operation:\n\t" \
          "BACKEND mode will bootstrap a new deployment of a pySRUP backend.\n\t" \
          "SERVER mode will generate the keys & credentials required for a C2 server instance.\n\n" \
          "In BACKEND mode, the following keys are always required:\n" \
          "\n\t* Broker CA Cert\n\t* Broker CA Key\n\t* Broker Cert\n\t* Broker Key\n\t* KeyEx Public Key" \
          "\n\t* KeyEx Private Key\n\n" \
          "\tOptionally the tool can also generate SRUP keys & an MQTT Broker key & certificate for a SRUP C2 " \
          "\n\tapplication. The tool may also optionally generate suitable full-chain certificates for the" \
          "\n\twebserver: for use in situations where the server is not using a public Certificate Authority" \
          "\n\t(such as Let's Encrypt) to validate the identity nof the webserver.\n\n" \
          "\tUsing a public CA for the webserver is preferable when hosting on the public Internet; and the use" \
          "\n\tof a private root CA is only recommended for non-Internet connected networks. Any SRUP client" \
          "\n\tapplications (devices or servers) will need to be supplied with a copy of the web.crt file to " \
          "\n\tensure they can access resources from the server."\
          "\n\nIn SERVER mode the tool will generate:\n\n\t* C2 Server (SRUP) Private Key" \
          "\n\t* C2 Server (SRUP) Public Key\n\t* C2 Server MQTT Broker Key\n\t* C2 Server MQTT Broker Certificate" \
          "\n\t* C2 Server Token\n\n\tThe SRUP keys define the identity of the C2 server; and the Token is used when " \
          "registering the C2\n\tserver's identity with the KeyEx service.\n\n\tNOTE that the serverpath argument" \
          "must be specified when running the tool in SERVER mode."

parser = argparse.ArgumentParser(prog=__prog__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=introtext,
                                 allow_abbrev=False,
                                 epilog=__prog__ + " written by AJ Poulter (a.j.poulter@soton.ac.uk)"
                                 )

parser.add_argument('MODE',
                    action='store',
                    type=str,
                    help="Specify which mode to use. Must be one of BACKEND or SERVER. Use BACKEND to generate a set of"
                         " backend keys, or SERVER to generate a new C2 server identity & credentials")

parser.add_argument('--brokerpath',
                    action='store',
                    type=str,
                    required=False,
                    help="The path in which to store the MQTT Broker certificate & keys",
                    metavar="path")

parser.add_argument('--brokercapath',
                    action='store',
                    type=str,
                    required=False,
                    help="The path in which to store the CA certificate for the MQTT Broker",
                    metavar="path")

parser.add_argument('--keyexpath',
                    action='store',
                    type=str,
                    required=False,
                    help="The path in which to store the KeyEx keys",
                    metavar="path")

parser.add_argument('--webpath',
                    action='store',
                    type=str,
                    required='--webcerts' in sys.argv or '-w' in sys.argv,
                    help="The path in which to store the Webserver certificate & keys",
                    metavar="path")

parser.add_argument('--serverpath',
                    action="store",
                    type=str,
                    required=False,
                    help="An optional path in which to store keys and certificates for a C2 server application. No "
                         "server keys or certificates will be generated if this is omitted",
                    metavar="path")

parser.add_argument('--broker_url',
                    action='store',
                    type=str,
                    required=False,
                    help="The URL for the MQTT Broker",
                    metavar="url")

parser.add_argument('--issuer', '-i',
                    action='store',
                    type=str,
                    required=False,
                    help="The issuer organization name to use for the CA certificates (will default to 'SRUP Backend'"
                         " if not specified)")

parser.add_argument('--country', '-c',
                    action='store',
                    type=str,
                    required=False,
                    help="The two-character ISO country code to use for the certificates (will default to  'GB' if not"
                         " specified)")

parser.add_argument('--web_url',
                    action='store',
                    type=str,
                    required=False,
                    help="The optional URL for the webserver certificate (will default to localhost if not specified)",
                    metavar="url")


parser.add_argument('--quiet', '-q',
                    action='store_true',
                    required=False,
                    help="Quiet mode. Do not print the names of keys & certificates as they are generated")

parser.add_argument('--ca_file',
                    action='store',
                    required=False,
                    help="The filename of the MQTT Broker CA file. Note that this MUST be specified in SERVER mode, "
                         "and must not be specified in BACKEND mode",
                    metavar="file")

parser.add_argument('--ca_cert_file',
                    action='store',
                    required=False,
                    help="The filename of the MQTT Broker CA certificate file. Note that this MUST be specified in"
                         " SERVER mode, and must not be specified in BACKEND mode",
                    metavar="file")

parser.add_argument('--keyex_key',
                    action='store',
                    required=False,
                    help="The filename of the KeyEx (SRUP) Private Key - to be used to sign the server key. Note that"
                         "this MUST be specified in SERVER mode, and must not tbe specified in BACKEND mode",
                    metavar='file')

parser.add_argument('--version',
                    action='store_true',
                    required=False,
                    help="Print the version number of and exits")

args = parser.parse_args()

# We'll start by checking to see if the user just wants the version number...
if args.version:
    print(__prog__ + " " + __version__)
    sys.exit(0)

# The first thing to do now we're running for real is to see which MODE we're in...
if args.MODE == 'SERVER':
    server_mode = True
elif args.MODE == 'BACKEND':
    server_mode = False
else:
    # We have an invalid MODE... So we'll stop here.
    sys.exit("{} is not a valid mode.".format(args.MODE))

if not server_mode:
    # e.g. we're in BACKEND mode...
    # We should check that if we have a country code – that it's valid...
    # We could be clever and check vs. the ISO standard but we'll just check the length is two chars;
    # and we'll convert to upper-case… The value isn't used for anything other than display when viewing the cert...

    if args.country is not None:
        if len(args.country) != 2:
            sys.exit("Invalid country code ({}) – must be two characters in length".format(args.country))
        else:
            args.country = args.country.upper()

    # Now check we have a sensible set of arguments. Argparse can't do this for us, as we're using a MODE select
    # so we have to do a bit more work ourselves...

    if args.ca_file is not None:
        sys.exit("ca_file should not be specified in BACKEND mode")

    if args.ca_cert_file is not None:
        sys.exit("ca_cert_file should not be specified in BACKEND mode")

    if args.serverpath is not None:
        sys.exit("serverpath should not be specified in BACKEND mode")

    if args.keyex_key is not None:
        sys.exit("keyex_key should not be specified in BACKEND mode")

    # Now we'll start by generating a key-pair for the KeyEx service to use...
    if not generate_SRUP_keys(keyex_pv_file="keyex.pem", keyex_pb_file="keyex_pub.pem", path=args.keyexpath):
        sys.exit("Error generating SRUP Keys")

    # Next we'll generate a CA root key for the broker.
    # We'll start by generating a key-pair for the KeyEx service to use...
    if not generate_broker_keys(path=args.brokerpath, ca_path=args.brokercapath, ca_key_file="broker_ca.key",
                                ca_cert_file="broker_ca.crt", broker_key_file="broker.key",
                                broker_cert_file="broker.crt", url=args.broker_url, country_name=args.country,
                                issuer=args.issuer):
        sys.exit("Error generating MQTT Broker Keys / Certificates")

    if args.webpath is not None:
        if not generate_webserver_keys(path=args.webpath, web_ca_key_file="web_ca.key", web_ca_cert_file="web_ca.crt",
                                       web_key_file="web.key", web_cert_file="web.crt", issuer=args.issuer,
                                       url=args.web_url, country_name=args.country):
            sys.exit("Error generating Web Server Keys / Certificates")
else:
    # We are in SERVER mode...
    # To begin - check our arguments...

    if args.ca_file is None:
        sys.exit("ca_file must be specified in SERVER mode")

    if args.ca_cert_file is None:
        sys.exit("ca_cert_file must be specified in SERVER mode")

    if args.serverpath is None:
        sys.exit("serverpath must be specified in SERVER mode")

    if args.keyex_key is None:
        sys.exit("keyex_key must be specified in SERVER mode")

    # We'll need to have some files passed in to work with (previous keys & certs) – so to start with we need to check
    # that we have them.
    # Start by generating the Server keypair...
    generate_Server_SRUP_keys(server_path=args.serverpath, server_pv_file="c2_server.pem",
                              server_pb_file="c2_server_pub.pem", server_token_file="c2_server.stk",
                              keyex_pv_key=args.keyex_key)

    # Next we'll generate the MQTT Broker key & cert. for the C2 Server...
    generate_server_broker_keys(server_path=args.serverpath, server_key_file="c2_server.key",
                                server_cert_file="c2_server.crt", ca_file=args.ca_file, cacert_file=args.ca_cert_file)
