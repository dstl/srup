import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

# The main test script for pySRUPLib's SRUP_Data() class...


def test_data_type():
    x = pySRUPLib.SRUP_Data()
    assert x.msg_type == pySRUPLib.__data_message_type()


def test_int8_data():
    MIN_DATA = -128
    MAX_DATA = 127
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_uint8_data():
    MIN_DATA = 0
    MAX_DATA = 255
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_int16_data():
    MIN_DATA = -32768
    MAX_DATA = 32767
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_uint16_data():
    MIN_DATA = 0x0000
    MAX_DATA = 0xFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_int32_data():
    MIN_DATA = -0x80000000
    MAX_DATA = 0x7FFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_uint32_data():
    MIN_DATA = 0x00000000
    MAX_DATA = 0xFFFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_int64_data():
    MIN_DATA = -0x8000000000000000
    MAX_DATA = 0x7FFFFFFFFFFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_uint64_data():
    MIN_DATA = 0x0000000000000000
    MAX_DATA = 0xFFFFFFFFFFFFFFFF
    STRING = "Test"
    FLOAT = 123.45

    x = pySRUPLib.SRUP_Data()

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


def test_double_data():
    MIN_DATA = sys.float_info.max
    MAX_DATA = sys.float_info.min
    STRING = "Test"

    x = pySRUPLib.SRUP_Data()

    x.double_data = MIN_DATA
    assert x.double_data == MIN_DATA

    x.double_data = MAX_DATA
    assert x.double_data == MAX_DATA

    with pytest.raises(TypeError):
        x.double_data = STRING


def test_string_data():
    SHORT_STRING = "Test"
    LONG_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-=_+{}[];':\",./<>?~|\\"
    LONGEST_STRING = ""

    for i in range(0, 65535):
        LONGEST_STRING += "x"

    assert(len(LONGEST_STRING) == 65535)

    x = pySRUPLib.SRUP_Data()
    x.bytes_data = SHORT_STRING
    assert x.bytes_data == SHORT_STRING

    x.bytes_data = LONG_STRING
    assert x.bytes_data == LONG_STRING

    x.bytes_data = LONGEST_STRING
    assert x.bytes_data == LONGEST_STRING


def test_data_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Data()

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


def test_data_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Data()

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


def test_data_id():
    x = pySRUPLib.SRUP_Data()

    SHORT_DATA_ID = "TEST_DATA"
    LONGER_DATA_ID = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LONGEST_DATA_ID = ""

    for i in range(0, 65535):
        LONGEST_DATA_ID += "x"

    assert x.data_id is None
    x.data_id = SHORT_DATA_ID
    assert x.data_id == SHORT_DATA_ID

    x.data_id = LONGER_DATA_ID
    assert x.data_id == LONGER_DATA_ID

    x.data_id = LONGEST_DATA_ID
    assert x.data_id == LONGEST_DATA_ID

    LONGEST_DATA_ID += "s"
    assert(len(LONGEST_DATA_ID) > 65535)

    x.data_id = LONGEST_DATA_ID
    assert x.data_id != LONGEST_DATA_ID
    assert x.data_id == LONGEST_DATA_ID[0:65535]


def test_data_token():
    x = pySRUPLib.SRUP_Data()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_data_signing():
    blank = ""

    x = pySRUPLib.SRUP_Data()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False

    x.data_id = "BOB"
    assert x.sign(keyfile) is False

    x.int8_data = 7
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True
    x.sequence_id = 43
    assert x.verify(pubkeyfile) is False


def test_data_serializer_int():
    x = pySRUPLib.SRUP_Data()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.data_id = "COUNT"
    x.uint8_data = 20
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_data_serializer_long_long_int():
    x = pySRUPLib.SRUP_Data()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.data_id = "COUNT"
    x.uint64_data = 0x1234567890ABCDEF
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_data_serializer_double():
    x = pySRUPLib.SRUP_Data()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.data_id = "COUNT"
    x.double_data = 1234567.89012345
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_data_serializer_string():
    x = pySRUPLib.SRUP_Data()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.data_id = "COUNT"
    x.bytes_data = "This is a test message that someone might want to send"
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_data_serializer_specific():
    x = pySRUPLib.SRUP_Data()
    x.token = 'b42c27f3-48bd-4ee6-bd86-09bae2e3a546'
    x.sequence_id = 17
    x.sender_id = 13389333505314606326
    x.data_id = 'IDENTIFICATION_RESPONSE'
    x.bytes_data = 'pySRUP version 1.0'
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_data_serialize_blank_token():
    x = pySRUPLib.SRUP_Data()
    x.token = ""
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False
    z = x.serialize()
    assert z is None


def test_data_generic_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data_id = "Text"
    data = "This is some text ..."

    x = pySRUPLib.SRUP_Data()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.data_id = data_id
    x.bytes_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__data_message_type()


def test_data_deserializer_int16():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data_id = "COUNT"
    data = 20

    x = pySRUPLib.SRUP_Data()
    y = pySRUPLib.SRUP_Data()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.data_id = data_id
    x.int16_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.data_id == data_id
    assert y.int16_data == data

    assert y.verify(pubkeyfile) is True


def test_data_deserializer_string():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data_id = "Text"
    data = "This is some text ..."

    x = pySRUPLib.SRUP_Data()
    y = pySRUPLib.SRUP_Data()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.data_id = data_id
    x.bytes_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.data_id == data_id
    assert y.bytes_data == data

    assert y.verify(pubkeyfile) is True


def test_data_deserializer_double():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data_id = "Temperature"
    data = 18.94

    x = pySRUPLib.SRUP_Data()
    y = pySRUPLib.SRUP_Data()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.data_id = data_id
    x.double_data = data

    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.data_id == data_id
    assert y.double_data == data

    assert y.verify(pubkeyfile) is True


def test_empty_object():
    x = pySRUPLib.SRUP_Data()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.data_id is None
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
