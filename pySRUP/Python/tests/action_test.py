import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

# The main test script for pySRUPLib's SRUP_Action() class...


def test_action_type():
    x = pySRUPLib.SRUP_Action()
    assert x.msg_type == pySRUPLib.__action_message_type()


def test_action_id():
    ZERO_ACTION = 0
    VALID_ACITON = 128
    MAX_ACTION = 255
    HIGH_ACTION = 512
    LOW_ACTION = -17

    x = pySRUPLib.SRUP_Action()
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


def test_action_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Action()

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


def test_action_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Action()

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


def test_action_token():
    x = pySRUPLib.SRUP_Action()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_action_signing():
    blank = ""
    
    x = pySRUPLib.SRUP_Action()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False
    
    x.action_id = 7
    assert x.sign(keyfile) is False
    
    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False
    
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True
    x.action_id = 6
    assert x.verify(pubkeyfile) is False


def test_serializer():
    x = pySRUPLib.SRUP_Action()
    x.action_id = 7
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is True
    z = x.serialize()


def test_serialize_blank_token():
    x = pySRUPLib.SRUP_Action()
    x.action_id = 0
    x.token = ""
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False
    z = x.serialize()


def test_deserializer():
    token = "TOKEN12345"
    action_id = 7
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    x = pySRUPLib.SRUP_Action()
    y = pySRUPLib.SRUP_Action()

    x.action_id = action_id
    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    assert x.sign(keyfile) is True
    z = x.serialize()
    
    assert y.deserialize(z) is True
    assert y.token == token
    assert y.action_id == action_id
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.verify(pubkeyfile) is True


def test_empty_object():
    x = pySRUPLib.SRUP_Action()
    assert x.token is None
    assert x.action_id is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.sign("") is False
