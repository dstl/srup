import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"


# The main test script for pySRUPLib's SRUP_Initiate() class...

def test_response_type():
    x = pySRUPLib.SRUP_Response()
    assert x.msg_type == pySRUPLib.__response_message_type()


def test_resonse_status():
    ZERO = 0
    VALID = 128
    MAX = 255
    HIGH = 512
    LOW = -17

    x = pySRUPLib.SRUP_Response()
    x.status = VALID
    assert x.status == VALID

    x.status = ZERO
    assert x.status == ZERO

    x.status = MAX
    assert x.status == MAX

    with pytest.raises(OverflowError):
        x.status = MAX + 1

    with pytest.raises(OverflowError):
        x.status = HIGH

    with pytest.raises(OverflowError):
        x.status = ZERO - 1

    with pytest.raises(OverflowError):
        x.status = LOW


def test_response_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Response()

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


def test_response_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Response()

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


def test_response_token():
    x = pySRUPLib.SRUP_Response()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_response_signing():
    blank = ""

    x = pySRUPLib.SRUP_Response()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    x.action_id = 7
    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False

    x.status = x.srup_response_status_resign_success()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True

    # Transpose a digit in the digest...
    x.status = x.srup_response_status_join_fail()
    assert x.verify(pubkeyfile) is False


def test_response_serializer():
    x = pySRUPLib.SRUP_Response()
    x.action_id = 7
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.status = x.srup_response_status_deregister_success()
    assert x.sign(keyfile) is True
    z = x.serialize()


def test_initiate_deserializer():
    token = "TOKEN12345"
    action_id = 7
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    status = pySRUPLib.SRUP_Response().srup_response_status_update_fail_file()

    x = pySRUPLib.SRUP_Response()
    y = pySRUPLib.SRUP_Response()

    x.action_id = action_id
    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.status = status

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.status == status


def test_initiate_generic_deserializer():
    token = "TOKEN12345"
    action_id = 7
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    status = pySRUPLib.SRUP_Response().srup_response_status_update_fail_file()

    x = pySRUPLib.SRUP_Response()
    i = pySRUPLib.SRUP_Generic()

    x.action_id = action_id
    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.status = status

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__response_message_type()


def test_empty_object():
    x = pySRUPLib.SRUP_Response()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.status is None
    assert x.sign("") is False


def test_response_status_values():

    # Here we'll use hard coded values to test that the correct implementation has been achieved from the C++ header...

    x = pySRUPLib.SRUP_Response()

    t = x.srup_response_status_update_success()
    assert t == 0x00

    t = x.srup_response_status_update_fail_server()
    assert t == 0xFD

    t = x.srup_response_status_update_fail_file()
    assert t == 0xFE

    t = x.srup_response_status_update_fail_digest()
    assert t == 0xFF

    t = x.srup_response_status_update_fail_http_error()
    assert t == 0xFC

    t = x.srup_response_status_activate_success()
    assert t == 0x10

    t = x.srup_response_status_activate_fail()
    assert t == 0x1F

    t = x.srup_response_status_action_success()
    assert t == 0x20

    t = x.srup_response_status_action_unknown()
    assert t == 0x2E

    t = x.srup_response_status_action_fail()
    assert t == 0x2F

    t = x.srup_response_status_data_type_unknown()
    assert t == 0x3F

    t = x.srup_response_status_join_success()
    assert t == 0x50

    t = x.srup_response_status_join_refused()
    assert t == 0x5E

    t = x.srup_response_status_join_fail()
    assert t == 0x5F

    t = x.srup_response_status_observed_join_valid()
    assert t == 0x60

    t = x.srup_response_status_observed_join_invalid()
    assert t == 0x6E

    t = x.srup_response_status_observed_join_fail()
    assert t == 0x6F

    t = x.srup_response_status_resign_success()
    assert t == 0x70

    t = x.srup_response_status_resign_fail()
    assert t == 0x7F

    t = x.srup_response_status_deregister_success()
    assert t == 0x80

    t = x.srup_response_status_deregister_fail()
    assert t == 0x8F
