import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

# The main test script for pySRUPLib's SRUP_Syndicated_Device_List() class...


def test_syndicated_dev_list_type():
    x = pySRUPLib.SRUP_Syndicated_Device_List()
    assert x.msg_type == pySRUPLib.__syndicated_device_list_message_type()


def test_syndicated_dev_list_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndicated_Device_List()

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


def test_syndicated_dev_list_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndicated_Device_List()

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


def test_syndicated_dev_list_token():
    x = pySRUPLib.SRUP_Syndicated_Device_List()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_syndicated_dev_list_sequence():
    x = pySRUPLib.SRUP_Syndicated_Device_List()
    assert x.device_sequence is None
    x.device_sequence = 0xFFFFFFFF
    assert x.device_sequence == 0xFFFFFFFF
    with pytest.raises(OverflowError):
        x.device_sequence = 0x100000000


def test_syndicated_dev_list_dev_id():
    x = pySRUPLib.SRUP_Syndicated_Device_List()
    assert x.device_id is None
    x.device_id = 0xFFFFFFFFFFFFFFFF
    assert x.device_id == 0xFFFFFFFFFFFFFFFF
    with pytest.raises(OverflowError):
        x.device_id = 0x10000000000000000


def test_syndicated_dev_list_signing():
    blank = ""

    x = pySRUPLib.SRUP_Syndicated_Device_List()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.device_sequence = 17
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False

    x.device_id = 0xFFFF5F5F5F5F5F5F
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True

    # Transpose a digit in the digest...
    x.sequence_id = 0x5F5F5F5F5F5F5F5F - 1
    assert x.verify(pubkeyfile) is False


def test_syndicated_dev_list_serializer():
    x = pySRUPLib.SRUP_Syndicated_Device_List()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.device_sequence = 0xABCDEF78
    x.device_id = 0xFFDDBB0099
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_syndicated_dev_list_generic_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    dev_seq = 0x12345678
    dev_id = 0x7765412340ABCDEF

    x = pySRUPLib.SRUP_Syndicated_Device_List()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.device_sequence = dev_seq
    x.device_id = dev_id

    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__syndicated_device_list_message_type()


def test_syndicated_dev_list_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    dev_seq = 0xFFFFFFFF
    dev_id = 0x76392017FDC32174

    x = pySRUPLib.SRUP_Syndicated_Device_List()
    y = pySRUPLib.SRUP_Syndicated_Device_List()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.device_sequence = dev_seq
    x.device_id = dev_id

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert z is not None
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.device_sequence == dev_seq
    assert y.device_id == dev_id


def test_empty_object():
    x = pySRUPLib.SRUP_Syndicated_Device_List()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.device_id is None
    assert x.device_sequence is None
    assert x.sign("") is False
