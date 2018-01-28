import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

# The main test script for pySRUPLib's SRUP_Initiate() class...

def test_initiate_type():
    x = pySRUPLib.SRUP_Initiate()
    assert x.msg_type == pySRUPLib.__initiate_message_type()


def test_initiate_target():
    x = pySRUPLib.SRUP_Initiate()
    assert x.target is None
    x.target = 0x7C7C7C7C7C7C7C7C
    assert x.target == 0x7C7C7C7C7C7C7C7C


def test_initiate_url():
    x = pySRUPLib.SRUP_Initiate()
    assert x.url is None
    x.url = "TEST URL"
    assert x.url == "TEST URL"


def test_initiate_digest():
    x = pySRUPLib.SRUP_Initiate()
    assert x.digest is None
    x.digest = "TEST DIGEST"
    assert x.digest == "TEST DIGEST"


def test_initiate_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Initiate()

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


def test_initiate_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Initiate()

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


def test_initiate_token():
    x = pySRUPLib.SRUP_Initiate()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_initiate_signing():
    blank = ""

    x = pySRUPLib.SRUP_Initiate()
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

    x.target = 0x7C7C7C7C7C7C7C7C
    assert x.sign(keyfile) is False

    x.digest = "8317c2d45ef7d42d7abe4f2eb5f53787e158b78680d67e99615b8799ef9936eb"
    assert x.sign(keyfile) is False

    x.url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True

    # Transpose a digit in the digest...
    x.digest = "8317c2d45ef7d42d7abe4f2eb5f53787e158b78608d67e99615b8799ef9936eb"
    assert x.verify(pubkeyfile) is False


def test_initiate_serializer():
    x = pySRUPLib.SRUP_Initiate()
    x.action_id = 7
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.digest = "8317c2d45ef7d42d7abe4f2eb5f53787e158b78680d67e99615b8799ef9936eb"
    x.url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    x.target = 0x7C7C7C7C7C7C7C7C
    assert x.sign(keyfile) is True
    z = x.serialize()


def test_initiate_deserializer():
    token = "TOKEN12345"
    action_id = 7
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    digest = "8317c2d45ef7d42d7abe4f2eb5f53787e158b78680d67e99615b8799ef9936eb"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    target = 0x7C7C7C7C7C7C7C7C

    x = pySRUPLib.SRUP_Initiate()
    y = pySRUPLib.SRUP_Initiate()

    x.action_id = action_id
    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.target = target
    x.digest = digest
    x.url = url

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.target == target
    assert y.url == url
    assert y.digest == digest


def test_empty_object():
    x = pySRUPLib.SRUP_Initiate()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.url is None
    assert x.digest is None
    assert x.target is None
    assert x.sign("") is False