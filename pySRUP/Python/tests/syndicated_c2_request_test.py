import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

# The main test script for pySRUPLib's SRUP_Syndicated_C2_Request() class...


def test_c2_req_type():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    assert x.msg_type == pySRUPLib.__syndicated_c2_request_message_type()


def test_c2_req_int8_data():
    MIN_DATA = -128
    MAX_DATA = 127
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.int8_data = MIN_DATA
    assert x.int8_data == MIN_DATA

    x.int8_data = MAX_DATA
    assert x.int8_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.int8_data = MAX_DATA + 1

    with pytest.raises(OverflowError):
        x.int8_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.int8_data = STRING

    with pytest.raises(TypeError):
        x.int8_data = FLOAT


def test_c2_req_uint8_data():
    MIN_DATA = 0
    MAX_DATA = 255
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.uint8_data = MIN_DATA
    assert x.uint8_data == MIN_DATA

    x.uint8_data = MAX_DATA
    assert x.uint8_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.uint8_data = MAX_DATA + 1

    with pytest.raises(OverflowError):
        x.uint8_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.uint8_data = STRING

    with pytest.raises(TypeError):
        x.uint8_data = FLOAT


def test_c2_req_int16_data():
    MIN_DATA = -32768
    MAX_DATA = 32767
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.int16_data = MIN_DATA
    assert x.int16_data == MIN_DATA

    x.int16_data = MAX_DATA
    assert x.int16_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.int16_data = MAX_DATA + 1

    with pytest.raises(OverflowError):
        x.int16_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.int16_data = STRING

    with pytest.raises(TypeError):
        x.int16_data = FLOAT


def test_c2_req_uint16_data():
    MIN_DATA = 0x0000
    MAX_DATA = 0xFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.uint16_data = MIN_DATA
    assert x.uint16_data == MIN_DATA

    x.uint16_data = MAX_DATA
    assert x.uint16_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.uint16_data = MAX_DATA + 1

    with pytest.raises(OverflowError):
        x.uint16_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.uint16_data = STRING

    with pytest.raises(TypeError):
        x.uint16_data = FLOAT


def test_c2_req_int32_data():
    MIN_DATA = -0x80000000
    MAX_DATA = 0x7FFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.int32_data = MIN_DATA
    assert x.int32_data == MIN_DATA

    x.int32_data = MAX_DATA
    assert x.int32_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.int32_data = MAX_DATA+1

    with pytest.raises(OverflowError):
        x.int32_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.int32_data = STRING

    with pytest.raises(TypeError):
        x.int32_data = FLOAT


def test_c2_req_uint32_data():
    MIN_DATA = 0x00000000
    MAX_DATA = 0xFFFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.uint32_data = MIN_DATA
    assert x.uint32_data == MIN_DATA

    x.uint32_data = MAX_DATA
    assert x.uint32_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.uint32_data = MAX_DATA + 1

    with pytest.raises(OverflowError):
        x.uint32_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.uint32_data = STRING

    with pytest.raises(TypeError):
        x.uint32_data = FLOAT


def test_c2_req_int64_data():
    MIN_DATA = -0x8000000000000000
    MAX_DATA = 0x7FFFFFFFFFFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.int64_data = MIN_DATA
    assert x.int64_data == MIN_DATA

    x.int64_data = MAX_DATA
    assert x.int64_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.int64_data = MAX_DATA+1

    with pytest.raises(OverflowError):
        x.int64_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.int64_data = STRING

    with pytest.raises(TypeError):
        x.int64_data = FLOAT


def test_c2_req_uint64_data():
    MIN_DATA = 0x0000000000000000
    MAX_DATA = 0xFFFFFFFFFFFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.uint64_data = MIN_DATA
    assert x.uint64_data == MIN_DATA

    x.uint64_data = MAX_DATA
    assert x.uint64_data == MAX_DATA

    with pytest.raises(OverflowError):
        x.uint64_data = MAX_DATA + 1

    with pytest.raises(OverflowError):
        x.uint64_data = MIN_DATA - 1

    with pytest.raises(TypeError):
        x.uint64_data = STRING

    with pytest.raises(TypeError):
        x.uint64_data = FLOAT


def test_c2_req_double_data():
    MIN_DATA = sys.float_info.max
    MAX_DATA = sys.float_info.min
    STRING = "Test"

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.double_data = MIN_DATA
    assert x.double_data == MIN_DATA

    x.double_data = MAX_DATA
    assert x.double_data == MAX_DATA

    with pytest.raises(TypeError):
        x.double_data = STRING


def test_c2_req_string_data():
    SHORT_STRING = "Test"
    LONG_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-=_+{}[];':\",./<>?~|\\"
    LONGEST_STRING = ""

    for i in range(0, 65535):
        LONGEST_STRING += "x"

    assert(len(LONGEST_STRING) == 65535)

    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    x.bytes_data = SHORT_STRING
    assert x.bytes_data == SHORT_STRING

    x.bytes_data = LONG_STRING
    assert x.bytes_data == LONG_STRING

    x.bytes_data = LONGEST_STRING
    assert x.bytes_data == LONGEST_STRING


def test_c2_req_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

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


def test_c2_req_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndicated_C2_Request()

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


def test_c2_req_req_id():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()

    data_id = 0xFF

    assert x.req_id is None
    x.req_id = data_id
    assert x.req_id == data_id


def test_c2_req_token():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_c2_req_signing():
    blank = ""

    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False

    x.req_id = 0x09
    assert x.sign(keyfile) is False

    x.int8_data = 7
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True
    x.sequence_id = 43
    assert x.verify(pubkeyfile) is False


def test_c2_req_serializer_int():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.req_id = 0x31
    x.uint8_data = 20
    x.source_id = 0x20001
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_c2_req_data_serializer_long_long_int():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.req_id = 0x61
    x.uint64_data = 0x1234567890ABCDEF
    x.source_id = 0xFFFFFFFFFFFFFFFF
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_c2_req_data_serializer_double():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.req_id = 0x11
    x.source_id = 0xFFFFFFFFFFFFFFFF
    x.double_data = 1234567.89012345
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_c2_req_data_serializer_string():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.source_id = 0xFFFFFFFFFFFFFFFF
    x.req_id = 0x07
    x.bytes_data = "This is a test message that someone might want to send"
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_c2_req_serialize_blank_token():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    x.token = ""
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.req_id = 0x00
    assert x.sign(keyfile) is False
    z = x.serialize()
    assert z is None


def test_c2_req_generic_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    req_id = 0xF8
    data = "This is some text ..."
    source = 0x00011187643212356

    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.req_id = req_id
    x.bytes_data = data
    x.source_id = source

    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__syndicated_c2_request_message_type()


def test_c2_req_data_deserializer_int16():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    req_id = 0x54
    data = 20

    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    y = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.req_id = req_id
    x.int16_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.req_id == req_id
    assert y.int16_data == data

    assert y.verify(pubkeyfile) is True


def test_c2_req_data_deserializer_string():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    req_id = 0xD1
    data = "This is some text ..."

    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    y = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.req_id = req_id
    x.bytes_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.req_id == req_id
    assert y.bytes_data == data

    assert y.verify(pubkeyfile) is True


def test_c2_req_data_deserializer_double():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    req_id = 0x1A
    data = 18.94

    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    y = pySRUPLib.SRUP_Syndicated_C2_Request()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.req_id = req_id
    x.double_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.req_id == req_id
    assert y.double_data == data
    assert y.verify(pubkeyfile) is True


def test_empty_object():
    x = pySRUPLib.SRUP_Syndicated_C2_Request()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.req_id is None
    assert x.bytes_data is None
    assert x.int8_data is None
    assert x.uint8_data is None
    assert x.int16_data is None
    assert x.uint16_data is None
    assert x.int32_data is None
    assert x.uint32_data is None
    assert x.int64_data is None
    assert x.uint64_data is None
    assert x.float_data is None
    assert x.double_data is None
    assert x.sign("") is False
