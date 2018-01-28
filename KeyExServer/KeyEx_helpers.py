import random
import configparser
import uuid


def check_valid_json(data):
    # We need to see if the keys exist - so we must use xxx.get()
    if data.get('identity') is None:
        return False

    if data.get('key') is None:
        return False

    if data.get('type') is None:
        return False

    return True


def missing_json(data):
    missing = []
    if data.get('key') is None:
        missing.append('key')
    if data.get('identity') is None:
        missing.append('identity')
    if data.get('type') is None:
        missing.append('type')

    return missing


def charval(c):
    if c < 1:
        return ''
    elif 1 <= c <= 26:
        return chr(c+64)
    elif 27 <= c <= 52:
        return chr((c-26)+96)
    elif 53 <= c <= 62:
        return chr((c-52)+47)
    else:
        return ''


# Here's a demo function to give us something to return
def random_key():
    key = ''
    for i in range(32):
        key += charval(random.randint(1, 62))
    return key


# This will return the key from a file...
def keyfile(filename):
    key = ''
    with open(filename, 'r') as f:
        for line in f:
            if line[0:5] != "-----":
                key += line[:-1]
    return key


# This will back-convert the key stored in the database to the format that the RSA tools are expecting to see...
# Essentially it's the same as the above in reverse - but we write to a string, not to file.
def fixkey(k):
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


def _fatal_error(log, message, error_code):
    log.error(message)
    exit(error_code)


def _config_section_error_text(section):
    return "Config File missing section [" + str(section) + "]"


def _config_option_error_text(option):
    return "Config File missing option '" + str(option) + "'"


def get_config(log, config):
    """Load the config data from the specified configparser..."""

    # We start with a set of the "critical" options to load – if any of these fail, we'll abort the start-up...
    # The structure here reflects the structure of the config file – two 'sections', each containing 'options'.
    # Note that we exclude the identity option from the set for automatic loading...
    config_to_load = {"Settings": ["broker", "database"], "Identity": ["private_key_file", "public_key_file"],
                      "CA": ["CA_key_file", "CA_cert_file"]}
    settings = {}

    # We'll iterate through the config_to_load items: for each option we'll try to load it from the config, and
    # then we'll add it to the (flat) settings dictionary which we'll return.
    for section, options in config_to_load.items():
        for option in options:
            try:
                item = config.get(section, option)
                settings.update({option: item})

            # If anything fails we'll invoke a fatal error – either because the section in question is missing...
            except configparser.NoSectionError:
                _fatal_error(log, _config_section_error_text(section), -3)

            # ... or the specific option is missing
            except configparser.NoOptionError:
                _fatal_error(log, _config_option_error_text(option), -2)

    # Having done the main set; there's one additional option to try to load from the config: the server identity.
    # This one however is genuinely optional; and so if it's not specified, we'll generate a uuid to use instead.
    try:
        identity = config.get("Identity", "identity")
        settings.update({"identity": identity})

    # Note the same fatal error if the section is missing (although if we've got here that shouldn't be possible!)
    except configparser.NoSectionError:
        _fatal_error(log, _config_section_error_text("Identity"), -3)

    # Generate the half-uuid, and log a warning if it's not specified.
    except configparser.NoOptionError:
        identity = hex(uuid.uuid4().int >> 64)[2:]
        log.warning("No server identity was specified – using auto-generated ID")
        settings.update({"identity": identity})

    return settings
