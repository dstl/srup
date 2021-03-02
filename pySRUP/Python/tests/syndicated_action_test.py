import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

# The main test script for pySRUPLib's SRUP_Syndicated_Action() class...


def test_syndicated_action_request_type():
    x = pySRUPLib.SRUP_Syndicated_Action()
    assert x.msg_type == pySRUPLib.__syndicated_action_message_type()


def test_action_id():
    ZERO_ACTION = 0
    VALID_ACITON = 128
    MAX_ACTION = 255
    HIGH_ACTION = 512
    LOW_ACTION = -17

    x = pySRUPLib.SRUP_Syndicated_Action()
    x.action_id = VALID_ACITON
    assert x.action_id == VALID_ACITON

    x.action_id = ZERO_ACTION
    assert x.action_id == ZERO_ACTION

    x.action_id = MAX_ACTION
    assert x.action_id == MAX_ACTION

    with pytest.raises(OverflowError):
        x.action_id = MAX_ACTION + 1

    with pytest.raises(OverflowError):
        x.action_id = HIGH_ACTION

    with pytest.raises(OverflowError):
        x.action_id = ZERO_ACTION - 1

    with pytest.raises(OverflowError):
        x.action_id = LOW_ACTION


def test_syndicated_action_request_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndicated_Action()

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


def test_syndicated_action_request_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndicated_Action()

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


def test_syndicated_action_request_token():
    x = pySRUPLib.SRUP_Syndicated_Action()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_syndicated_action_request_target():
    x = pySRUPLib.SRUP_Syndicated_Action()
    assert x.target_id is None
    x.target_id = 0x76543210FEDCBA98
    assert x.target_id == 0x76543210FEDCBA98


def test_syndicated_action_request_signing():
    blank = ""

    x = pySRUPLib.SRUP_Syndicated_Action()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.action_id = 7
    assert x.sign(keyfile) is False

    x.target_id = 0x76543210FEDCBA98
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True

    # Transpose a digit in the digest...
    x.sequence_id = 0x5F5F5F5F5F5F5F5F - 1
    assert x.verify(pubkeyfile) is False


def test_syndicated_action_request_serializer():
    x = pySRUPLib.SRUP_Syndicated_Action()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.target_id = 0x76543210FEDCBA98
    x.action_id = 0xFE

    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_syndicated_action_request_serializer_errors():
    x = pySRUPLib.SRUP_Syndicated_Action()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.target_id = 0x76543210FEDCBA98

    # We have the action unset – so x.sign will return false
    if x.sign(keyfile):
        z = x.serialize()
        assert z is not None


def test_syndicated_action_request_generic_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    target_id = 0x76543210FEDCBA98
    action = 0x43

    x = pySRUPLib.SRUP_Syndicated_Action()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.target_id = target_id
    x.action_id = action

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__syndicated_action_message_type()


def test_syndicated_action_request_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    target_id = 0x76543210FEDCBA98
    action = 0x43

    x = pySRUPLib.SRUP_Syndicated_Action()
    y = pySRUPLib.SRUP_Syndicated_Action()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.target_id = target_id
    x.action_id = action

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.target_id == target_id
    assert y.action_id == action


def test_empty_object():
    x = pySRUPLib.SRUP_Syndicated_Action()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.target_id is None
    assert x.action_id is None
    assert x.sign("") is False
