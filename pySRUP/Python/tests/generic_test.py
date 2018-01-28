import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"


# The main test script for pySRUPLib's SRUP_Initiate() class...

def test_response_type():
    x = pySRUPLib.SRUP_Generic()
    assert x.msg_type == pySRUPLib.__generic_message_type()


def test_generic_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Generic()

    x.sequence_id = MAX_SEQID
    assert x.sequence_id == MAX_SEQID

    x.sequence_id = VALID_SEQID
    assert x.sequence_id == VALID_SEQID

    x.sequence_id = ZERO_SEQID
    assert x.sequence_id == ZERO_SEQID

    with pytest.raises(OverflowError):
        x.sequence_id = MAX_SEQID + 1

    with pytest.raises(OverflowError):
        x.sequence_id = ZERO_SEQID - 1


def test_generic_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Generic()

    x.sender_id = MAX_SENDER
    assert x.sender_id == MAX_SENDER

    x.sender_id = VALID_SENDER
    assert x.sender_id == VALID_SENDER

    x.sender_id = ZERO_SENDER
    assert x.sender_id == ZERO_SENDER

    with pytest.raises(OverflowError):
        x.sender_id = MAX_SENDER + 1

    with pytest.raises(OverflowError):
        x.sender_id = ZERO_SENDER - 1


def test_generic_token():
    x = pySRUPLib.SRUP_Generic()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_generic_signing():
    # Note: the protocol standard says we can't sign a generic message
    # (i.e. as we'd never send a generic message we'd sign the real message
    # and interpret as a generic on receipt
    blank = ""

    x = pySRUPLib.SRUP_Generic()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False


def test_generic_serializer():
    # Similarly we can't serialize a generic message...
    x = pySRUPLib.SRUP_Generic()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False


def test_deserializer_from_action():
    # To test deserialization - we need to start with a different message-type and then convert
    # back to a generic message...
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    action_id = 0x07

    x = pySRUPLib.SRUP_Action()
    y = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.action_id = action_id

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True

    # Remember we can't verify the generic message...
    assert y.verify(pubkeyfile) is False

    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    assert y.token == token


def test_deserializer_from_init():
    # To test deserialization - we need to start with a different message-type and then convert
    # back to a generic message...
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    url = "https://google.com"
    digest ="THIS IS A TEST VALUE FOR THE DIGEST"
    target = 0x7F7F7F7F7F7F7F7F

    x = pySRUPLib.SRUP_Initiate()
    y = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url
    x.digest = digest
    x.target = target

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True

    # Remember we can't verify the generic message...
    assert y.verify(pubkeyfile) is False

    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    assert y.token == token


def test_deserializer_from_response():
    # To test deserialization - we need to start with a different message-type and then convert
    # back to a generic message...
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    status = pySRUPLib.SRUP_Response().srup_response_status_update_fail_file()

    x = pySRUPLib.SRUP_Response()
    y = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    x.status = status

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True

    # Remember we can't verify the generic message...
    assert y.verify(pubkeyfile) is False

    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    assert y.token == token


def test_deserializer_from_activate():
    # To test deserialization - we need to start with a different message-type and then convert
    # back to a generic message...
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    x = pySRUPLib.SRUP_Activate()
    y = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True

    # Remember we can't verify the generic message...
    assert y.verify(pubkeyfile) is False

    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    assert y.token == token


def test_deserializer_from_data():
    # To test deserialization - we need to start with a different message-type and then convert
    # back to a generic message...
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    data = "This is some data that I might store in the data field"
    data_id = "A string"

    x = pySRUPLib.SRUP_Data()
    y = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.bytes_data = data
    x.data_id = data_id

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True

    # Remember we can't verify the generic message...
    assert y.verify(pubkeyfile) is False

    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    assert y.token == token


def test_empty_object():
    x = pySRUPLib.SRUP_Generic()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None


def test_invalid_deserialize():
    x = pySRUPLib.SRUP_Generic()
    junk = "12345".encode()
    q = x.deserialize(junk)
    assert q is False
