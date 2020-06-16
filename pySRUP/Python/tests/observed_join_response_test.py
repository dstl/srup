import sys
sys.path.append('../../../')

import pytest
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

priv_keystring = "-----BEGIN RSA PRIVATE KEY-----\n" \
                 "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n" \
                 "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n" \
                 "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n" \
                 "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n" \
                 "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n" \
                 "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n" \
                 "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n" \
                 "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n" \
                 "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n" \
                 "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n" \
                 "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n" \
                 "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n" \
                 "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n" \
                 "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n" \
                 "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n" \
                 "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n" \
                 "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n" \
                 "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n" \
                 "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n" \
                 "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n" \
                 "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n" \
                 "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n" \
                 "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n" \
                 "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n" \
                 "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n" \
                 "-----END RSA PRIVATE KEY-----"

pub_keystring = "-----BEGIN PUBLIC KEY-----\n" \
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n" \
                "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n" \
                "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n" \
                "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n" \
                "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n" \
                "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n" \
                "wQIDAQAB\n-----END PUBLIC KEY-----"


# The main test script for pySRUPLib's SRUP_Observed_Join_Response() class...

def test_join_request_type():
    x = pySRUPLib.SRUP_Observed_Join_Response()
    assert x.msg_type == pySRUPLib.__observed_join_response_message_type()


def test_join_request_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Observed_Join_Response()

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


def test_join_request_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Observed_Join_Response()

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


def test_join_request_token():
    x = pySRUPLib.SRUP_Observed_Join_Response()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_join_request_signing():
    blank = ""

    x = pySRUPLib.SRUP_Observed_Join_Response()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(keyfile) is False

    x.encrypt("0123456789ABCDEF", pubkeyfile)

    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True

    # Transpose a digit in the digest...
    x.sequence_id = 0x5F5F5F5F5F5F5F5F - 1
    assert x.verify(pubkeyfile) is False


def test_join_request_signing_keystring():
    blank = ""

    x = pySRUPLib.SRUP_Observed_Join_Response()
    assert x.sign_keystring(blank) is False
    assert x.sign_keystring(priv_keystring) is False

    x.token = "TOKEN12345"
    assert x.sign_keystring(priv_keystring) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign_keystring(priv_keystring) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign_keystring(priv_keystring) is False

    x.encrypt_keystring("0123456789ABCDEF", pub_keystring)

    assert x.sign_keystring(blank) is False
    assert x.sign_keystring(priv_keystring) is True

    assert x.verify_keystring(pub_keystring) is True

    # Transpose a digit in the digest...
    x.sequence_id = 0x5F5F5F5F5F5F5F5F - 1
    assert x.verify_keystring(pub_keystring) is False


def test_join_request_serializer():
    x = pySRUPLib.SRUP_Observed_Join_Response()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.encrypt("0123456789ABCDEF", pubkeyfile)
    assert x.sign(keyfile) is True
    z = x.serialize()


def test_join_request_serializer_keystring():
    x = pySRUPLib.SRUP_Observed_Join_Response()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.encrypt_keystring("0123456789ABCDEF", pub_keystring)
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()


def test_join_request_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF0123456789ABCDEF"

    x = pySRUPLib.SRUP_Observed_Join_Response()
    y = pySRUPLib.SRUP_Observed_Join_Response()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    x.encrypt(data, pubkeyfile)
    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    new_data = y.decrypt(keyfile)
    assert new_data == data


def test_join_request_deserializer_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF0123456789ABCDEF"

    x = pySRUPLib.SRUP_Observed_Join_Response()
    y = pySRUPLib.SRUP_Observed_Join_Response()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    x.encrypt_keystring(data, pub_keystring)
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id

    new_data = y.decrypt_keystring(priv_keystring)
    assert new_data == data


def test_join_request_generic_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF0123456789ABCDEF"

    x = pySRUPLib.SRUP_Observed_Join_Response()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    x.encrypt(data, pubkeyfile)
    assert x.sign(keyfile) is True
    z = x.serialize()

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__observed_join_response_message_type()


def test_join_request_generic_deserializer_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF0123456789ABCDEF"

    x = pySRUPLib.SRUP_Observed_Join_Response()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    x.encrypt_keystring(data, pub_keystring)
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__observed_join_response_message_type()


def test_encrypt_decrypt():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    data = "0123456789ABCDEF0123456789ABCDEF"

    long_data = "123456789012345678900123456789ABCDEF"
    shorter_data = "0123456789ABCDEF"
    short_data = "123"
    very_long_data = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890-=!@#$%^&*()_+[]{};':,./<>?\|"

    x = pySRUPLib.SRUP_Observed_Join_Response()
    y = pySRUPLib.SRUP_Observed_Join_Response()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    # The encrypted data is expected to be 16-bytes (32 char string)...
    # So assigning longer sequences will result in truncation...
    x.encrypt(long_data, pubkeyfile)
    assert x.decrypt(keyfile) == long_data[:32]
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.decrypt(keyfile) == long_data[:32]

    x.encrypt(very_long_data, pubkeyfile)
    assert x.decrypt(keyfile) == very_long_data[:32]
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.decrypt(keyfile) == very_long_data[:32]

    # ... whilst shorter sequences will be padded with 0x00's
    x.encrypt(short_data, pubkeyfile)
    padded_short_data = short_data.ljust(32, chr(0x00))
    assert x.decrypt(keyfile) == padded_short_data
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.decrypt(keyfile) == padded_short_data

    x.encrypt(shorter_data, pubkeyfile)
    padded_shorter_data = shorter_data.ljust(32, chr(0x00))
    assert x.decrypt(keyfile) == padded_shorter_data
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.decrypt(keyfile) == padded_shorter_data

    # We can use strings for short-hand – but the real data will be raw bytes...
    # So let's test that too.
    byte_data = chr(0x00)
    byte_data += chr(0x01)
    byte_data += chr(0x02)
    byte_data += chr(0x03)
    byte_data += chr(0x04)
    byte_data += chr(0x05)
    byte_data += chr(0x06)
    byte_data += chr(0x07)
    byte_data += chr(0x08)
    byte_data += chr(0x09)
    byte_data += chr(0x0A)
    byte_data += chr(0x0B)
    byte_data += chr(0x0C)
    byte_data += chr(0x0D)
    byte_data += chr(0x0E)
    byte_data += chr(0x0F)
    byte_data += chr(0x00)
    byte_data += chr(0x01)
    byte_data += chr(0x02)
    byte_data += chr(0x03)
    byte_data += chr(0x04)
    byte_data += chr(0x05)
    byte_data += chr(0x06)
    byte_data += chr(0x07)
    byte_data += chr(0x08)
    byte_data += chr(0x09)
    byte_data += chr(0x0A)
    byte_data += chr(0x0B)
    byte_data += chr(0x0C)
    byte_data += chr(0x0D)
    byte_data += chr(0x0E)
    byte_data += chr(0x0F)

    x.encrypt(byte_data, pubkeyfile)
    assert x.decrypt(keyfile) == byte_data
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.decrypt(keyfile) == byte_data

    # Lastly we'll test with a "regular" 32-character string.
    x.encrypt(data, pubkeyfile)
    assert x.decrypt(keyfile) == data
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.decrypt(keyfile) == data


def test_encrypt_decrypt_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    data = "0123456789ABCDEF0123456789ABCDEF"

    long_data = "1234567890123456789012345678901234567890"
    short_data = "123"
    very_long_data = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890-=!@#$%^&*()_+[]{};':,./<>?\|"

    x = pySRUPLib.SRUP_Observed_Join_Response()
    y = pySRUPLib.SRUP_Observed_Join_Response()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id

    # The encrypted data is expected to be 16-bytes...
    # Encoded as a 32-character string
    # So assigning longer sequences will result in truncation...
    x.encrypt_keystring(long_data, pub_keystring)
    assert x.decrypt_keystring(priv_keystring) == long_data[:32]
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.decrypt_keystring(priv_keystring) == long_data[:32]

    x.encrypt_keystring(very_long_data, pub_keystring)
    assert x.decrypt_keystring(priv_keystring) == very_long_data[:32]
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.decrypt_keystring(priv_keystring) == very_long_data[:32]

    # ... whilst shorter sequences will be padded with 0x00's
    x.encrypt_keystring(short_data, pub_keystring)
    padded_short_data = short_data.ljust(32, chr(0x00))
    assert x.decrypt_keystring(priv_keystring) == padded_short_data
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.decrypt_keystring(priv_keystring) == padded_short_data

    # We can use strings for short-hand – but the real data will be raw bytes...
    # So let's test that too.
    byte_data = chr(0x00)
    byte_data += chr(0x01)
    byte_data += chr(0x02)
    byte_data += chr(0x03)
    byte_data += chr(0x04)
    byte_data += chr(0x05)
    byte_data += chr(0x06)
    byte_data += chr(0x07)
    byte_data += chr(0x08)
    byte_data += chr(0x09)
    byte_data += chr(0x0A)
    byte_data += chr(0x0B)
    byte_data += chr(0x0C)
    byte_data += chr(0x0D)
    byte_data += chr(0x0E)
    byte_data += chr(0x0F)
    byte_data += chr(0x00)
    byte_data += chr(0x01)
    byte_data += chr(0x02)
    byte_data += chr(0x03)
    byte_data += chr(0x04)
    byte_data += chr(0x05)
    byte_data += chr(0x06)
    byte_data += chr(0x07)
    byte_data += chr(0x08)
    byte_data += chr(0x09)
    byte_data += chr(0x0A)
    byte_data += chr(0x0B)
    byte_data += chr(0x0C)
    byte_data += chr(0x0D)
    byte_data += chr(0x0E)
    byte_data += chr(0x0F)

    x.encrypt_keystring(byte_data, pub_keystring)
    assert x.decrypt_keystring(priv_keystring) == byte_data
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.decrypt_keystring(priv_keystring) == byte_data

    # Lastly we'll test with a "regular" 32-character string.
    x.encrypt_keystring(data, pub_keystring)
    assert x.decrypt_keystring(priv_keystring) == data
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.decrypt_keystring(priv_keystring) == data


def test_empty_object():
    x = pySRUPLib.SRUP_Observed_Join_Response()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.sign("") is False
    assert x.decrypt(keyfile) is None


def test_empty_object_keystring():
    x = pySRUPLib.SRUP_Observed_Join_Response()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.sign("") is False
    assert x.decrypt_keystring(priv_keystring) is None

