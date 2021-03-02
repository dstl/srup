import sys
sys.path.append('../../../')

import pytest
import uuid
import pySRUPLib

keyfile = "private_key.pem"
pubkeyfile = "public_key.pem"

priv_keystring = "-----BEGIN RSA PRIVATE KEY-----\n" \
                 "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDV7vjpCaQMagD2\n" \
                 "y72JvDiUt/o75Ryzt8fRx4efEyCs5Q5ylSc1ZFcKQivKXxuIfc1WTiRp5onpdmVb\n" \
                 "Kn9OOeJwHt2tc/NW3QbWLpnOpRle4fwUQmVcixX6bZFPDfpTWlqnlT813UOpsbIm\n" \
                 "eOhnbkVJZmYQC0tUDvZbZeoOORqB8QmSkjJOEdqiAbvJxCNI8iKjxGzbmJxhekNv\n" \
                 "t6ddN7BUCRxsc3f1V5p7O1HikQVX4Ae1pjXksGfqcWFSp3NKv+GSHqquTT8lcrVd\n" \
                 "6KZU1wo44N+vIT655vodZ9eNEcGFbnt2DWkEZcQ+XUINdgp0/jHu+rqax2CzX889\n" \
                 "Cjb+La61AgMBAAECggEBAIrKzSWzIYEETLfQmpj/Sd4CNhAhpitacgLBZlVnvW0t\n" \
                 "9d+UsKlM/cMkBvD2HxDAPTVe4PTrolGahEtPGOSRXTzMaZkcfqS+JK9T8GlGZ11N\n" \
                 "U5N5N/WALrQX3YviT6NAHUxX4Xh6omk3ZZLcIjroKX9jNZf3G9nfEylcxyqPFYly\n" \
                 "vag3zphRHPFB4oRZAxqrpySJmaWX5Osb+yE6h+R7Ro3NsTfZczmc7zk32deKe7eF\n" \
                 "Xnj8iZ9gWm58X8feUeHwcTznDN/FuZIGSq7Teim0ylfSYOvM16weiGebbcbvbcgf\n" \
                 "UoSbqYPkSChhLlws+6ukKDl/CKth2KuUSZq0rXAO6gkCgYEA8b0vkMZAUE1n0Y4E\n" \
                 "ZB8Vvl+ZOrvko1jhROQSuE0OyeOTR+7nWbDHhWc3hkUYq8Y47YIwLYWY+tcNQge1\n" \
                 "J/PrQ9rSnG9IZgHEIBLMzjYAhfnHLzcgi059zEWmycHBhrhcbze+sfIGyaCU1uUM\n" \
                 "xL8yRpt2U4vSr6oDVoMI+FOXJ5cCgYEA4o3b+RATNalGekQPkGsl2UbfquKtWLyu\n" \
                 "AY+MQ+FuEBwqQraWCMplbLf4vxtwaBqD3hwIiyXLx5cQqGaqnCnKqY6kRsEOcxjq\n" \
                 "0yiC4Z1L/2Vack6drtmRyAoK1rM1zilE5axk3AsTJoRwRFm6HGPyyp9TZyDPmhy0\n" \
                 "9fgRQn3EBZMCgYA0IIuFOHrd1hMxCOLBhEJ4Dr1IAQRIhP3ukQ/IVjV+K2iy9j1F\n" \
                 "Be3AQoWimnu7br8P2Cbzaf+W95CQUIEr4Fk3BJStzwFZnb/g+qzXOqXaPgZJlCWc\n" \
                 "ZIyT4+EXWISWvGKSSP8B+CKmj84ImNOsCV6aAyP82AXSg2K84PyqL7xEeQKBgBi1\n" \
                 "uERWCIJV0CYNvlTWGu6z2DlfN+Dx01jAO2A7+jEvoTxdhce3q5BMEIlniL8SBUf4\n" \
                 "bsYefTdrtplneTxHIp+Tuz8sV1MeaJ5XUM8ixOM6Pr8w6+niORBEaCI6saemwKj8\n" \
                 "QJPvcUtGLqiF0NK/4/9NmV8qKPp6HxKk190UsoiZAoGASToeRT/YjRL2vAGQEU3j\n" \
                 "7NE2y8P9r++OHhiZtoLEKxZ2WdlUGsWvMgeBnBTYL0W3WRUuThfQGkECVtlhnZ4x\n" \
                 "h80hagxVYSJ5u3zPpLUSsRKEId4uRT44N3QAIHe2VRYafrPIK24RmFu3bQikYkR1\n" \
                 "U40unkjk0wnzqnWzubjP3+o=\n" \
                 "-----END RSA PRIVATE KEY-----"

pub_keystring = "-----BEGIN PUBLIC KEY-----\n" \
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1e746QmkDGoA9su9ibw4\n" \
                "lLf6O+Ucs7fH0ceHnxMgrOUOcpUnNWRXCkIryl8biH3NVk4kaeaJ6XZlWyp/Tjni\n" \
                "cB7drXPzVt0G1i6ZzqUZXuH8FEJlXIsV+m2RTw36U1pap5U/Nd1DqbGyJnjoZ25F\n" \
                "SWZmEAtLVA72W2XqDjkagfEJkpIyThHaogG7ycQjSPIio8Rs25icYXpDb7enXTew\n" \
                "VAkcbHN39VeaeztR4pEFV+AHtaY15LBn6nFhUqdzSr/hkh6qrk0/JXK1XeimVNcK\n" \
                "OODfryE+ueb6HWfXjRHBhW57dg1pBGXEPl1CDXYKdP4x7vq6msdgs1/PPQo2/i2u\n" \
                "tQIDAQAB\n" \
                "-----END PUBLIC KEY-----"


# The main test script for pySRUPLib's SRUP_Syndication_Init() class...
def test_syndication_init_type():
    x = pySRUPLib.SRUP_Syndication_Init()
    assert x.msg_type == pySRUPLib.__syndication_init_message_type()


def test_syndication_init_url():
    x = pySRUPLib.SRUP_Syndication_Init()
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    assert x.url is None
    x.url = url
    assert x.url == url


def test_syndication_init_seqid():
    MAX_SEQID = 0xFFFFFFFFFFFFFFFF
    ZERO_SEQID = 0x00
    VALID_SEQID = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndication_Init()

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


def test_syndication_init_sender():
    MAX_SENDER = 0xFFFFFFFFFFFFFFFF
    ZERO_SENDER = 0x00
    VALID_SENDER = 0x7FFFFFFFFFFFFFE7

    x = pySRUPLib.SRUP_Syndication_Init()

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


def test_syndication_init_token():
    x = pySRUPLib.SRUP_Syndication_Init()
    assert x.token is None
    x.token = "TEST_TOKEN"
    assert x.token == "TEST_TOKEN"


def test_syndication_init_signing():
    blank = ""

    x = pySRUPLib.SRUP_Syndication_Init()
    assert x.sign(blank) is False
    assert x.sign(keyfile) is False

    x.token = "TOKEN12345"
    assert x.sign(keyfile) is False

    x.encrypt("0123456789ABCDEF", pubkeyfile)
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign(keyfile) is False

    x.url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    assert x.sign(keyfile) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign(blank) is False
    assert x.sign(keyfile) is True

    assert x.verify(pubkeyfile) is True

    # Transpose a digit in the digest...
    x.sequence_id = 0x5F5F5F5F5F5F5F5F - 1
    assert x.verify(pubkeyfile) is False


def test_syndication_init_signing_keystring():
    blank = ""

    x = pySRUPLib.SRUP_Syndication_Request()
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


def test_syndication_init_serializer():
    x = pySRUPLib.SRUP_Syndication_Init()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.encrypt("0123456789ABCDEF", pubkeyfile)
    x.url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    assert x.sign(keyfile) is True
    z = x.serialize()
    assert z is not None


def test_syndication_init_serializer_keystring():
    x = pySRUPLib.SRUP_Syndication_Init()
    x.token = "TOKEN12345"
    x.sequence_id = 0x1234567890ABCDEF
    x.sender_id = 0x5F5F5F5F5F5F5F5F
    x.encrypt_keystring("0123456789ABCDEF", pub_keystring)
    x.url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert z is not None


def test_syndication_init_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF0123456789ABCDEF"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"

    x = pySRUPLib.SRUP_Syndication_Init()
    y = pySRUPLib.SRUP_Syndication_Init()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    x.encrypt(data, pubkeyfile)
    assert x.sign(keyfile) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.url == url

    new_data = y.decrypt(keyfile)
    assert new_data == data


def test_syndication_init_request_deserializer_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF0123456789ABCDEF"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"

    x = pySRUPLib.SRUP_Syndication_Init()
    y = pySRUPLib.SRUP_Syndication_Init()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    x.encrypt_keystring(data, pub_keystring)
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.url == url

    new_data = y.decrypt_keystring(priv_keystring)
    assert new_data == data


def test_syndication_init_generic_deserializer():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"

    x = pySRUPLib.SRUP_Syndication_Init()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    x.encrypt(data, pubkeyfile)
    assert x.sign(keyfile) is True
    z = x.serialize()

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__syndication_init_message_type()


def test_syndication_init_generic_deserializer_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    data = "0123456789ABCDEF"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"

    x = pySRUPLib.SRUP_Syndication_Init()
    i = pySRUPLib.SRUP_Generic()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    x.encrypt_keystring(data, pub_keystring)
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()

    assert i.deserialize(z) is True
    assert i.msg_type == pySRUPLib.__syndication_init_message_type()


def test_syndication_init_encrypt_decrypt():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    data = "0123456789ABCDEF0123456789ABCDEF"

    long_data = "1234567890123456789012345678901234567890"
    short_data = "123"
    very_long_data = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890-=!@#$%^&*()_+[]{};':,./<>?\\|"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"

    x = pySRUPLib.SRUP_Syndication_Init()
    y = pySRUPLib.SRUP_Syndication_Init()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    # The encrypted data is expected to be 16-bytes...
    # Typically this will be stored as a 32-character string
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

    # We might want to use raw-bytes...
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


def test_syndication_init_encrypt_decrypt_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F

    data = "0123456789ABCDEF0123456789ABCDEF"

    long_data = "1234567890123456789012345678901234567890"
    short_data = "123"
    very_long_data = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890-=!@#$%^&*()_+[]{};':,./<>?\\|"
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"

    x = pySRUPLib.SRUP_Syndication_Init()
    y = pySRUPLib.SRUP_Syndication_Init()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    # The encrypted data is expected to be 32-bytes...
    # So assigning longer sequences will result in truncation...
    # (See elsewhere in the tests for notes).
    x.encrypt_keystring(long_data, pub_keystring)
    assert x.decrypt_keystring(priv_keystring) == long_data[:32]
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.decrypt_keystring(priv_keystring) == long_data[:32]
    assert y.url == url

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
    assert y.url == url


def test_empty_object():
    x = pySRUPLib.SRUP_Syndication_Init()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.url is None
    assert x.sign("") is False
    assert x.decrypt(keyfile) is None


def test_empty_object_keystring():
    x = pySRUPLib.SRUP_Syndication_Init()
    assert x.token is None
    assert x.sequence_id is None
    assert x.sender_id is None
    assert x.url is None
    assert x.sign("") is False
    assert x.decrypt_keystring(priv_keystring) is None


def test_syndication_init_uuid_signing_keystring():
    blank = ""
    uid = uuid.uuid4().bytes

    x = pySRUPLib.SRUP_Syndication_Init()
    assert x.sign_keystring(blank) is False
    assert x.sign_keystring(priv_keystring) is False

    x.url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    assert x.sign_keystring(priv_keystring) is False

    x.token = "TOKEN12345"
    assert x.sign_keystring(priv_keystring) is False

    x.encrypt_keystring(uid, pub_keystring)
    assert x.sign(keyfile) is False

    x.sequence_id = 0x1234567890ABCDEF
    assert x.sign_keystring(priv_keystring) is False

    x.sender_id = 0x5F5F5F5F5F5F5F5F
    assert x.sign_keystring(blank) is False
    assert x.sign_keystring(priv_keystring) is True

    assert x.verify_keystring(pub_keystring) is True


def test_syndication_init_uuid_deserializer_keystring():
    token = "TOKEN12345"
    seq_id = 0x1234567890ABCDEF
    send_id = 0x5F5F5F5F5F5F5F5F
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    uid = uuid.uuid4().hex

    x = pySRUPLib.SRUP_Syndication_Init()
    y = pySRUPLib.SRUP_Syndication_Init()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    x.encrypt_keystring(uid, pub_keystring)
    assert x.sign_keystring(priv_keystring) is True
    z = x.serialize()

    assert y.deserialize(z) is True
    assert y.verify_keystring(pub_keystring) is True
    assert y.token == token
    assert y.sender_id == send_id
    assert y.sequence_id == seq_id
    assert y.url == url

    new_data = y.decrypt_keystring(priv_keystring)
    assert new_data == uid


def test_syndication_init_real_world_encrypt_decrypt():
    token = 'fb47ce0f-aa3f-43f6-a3ac-c05e6d7ca0dc'
    seq_id = 189
    send_id = 13389333505314606326
    url = "http://www.really-long-url.example.com/longpath/to/the/files/we_might/need.py"
    data = "636dd7ad8c004d09b2c391d0cc3aa2b0"

    assert len(data) == 32

    x = pySRUPLib.SRUP_Syndication_Init()
    y = pySRUPLib.SRUP_Syndication_Init()

    x.token = token
    x.sequence_id = seq_id
    x.sender_id = send_id
    x.url = url

    x.encrypt_keystring(data, pub_keystring)
    r_data = x.decrypt(keyfile)
    assert r_data == data
    assert len(r_data) == 32

    assert x.sign(keyfile) is True
    z = x.serialize()
    assert y.deserialize(z) is True
    assert y.verify(pubkeyfile) is True

    r_data_y = y.decrypt(keyfile)
    assert r_data_y == data
    assert len(r_data_y) == 32
    assert y.url == url
