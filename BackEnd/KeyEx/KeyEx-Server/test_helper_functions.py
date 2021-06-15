import KeyEx_helpers


def test_keygen_charval():
    # Test all of the boundary conditions for charval() – including out of range...
    assert KeyEx_helpers.charval(0) == ''
    assert KeyEx_helpers.charval(1) == 'A'
    assert KeyEx_helpers.charval(26) == 'Z'
    assert KeyEx_helpers.charval(27) == 'a'
    assert KeyEx_helpers.charval(52) == 'z'
    assert KeyEx_helpers.charval(53) == '0'
    assert KeyEx_helpers.charval(62) == '9'
    assert KeyEx_helpers.charval(63) == ''
    assert KeyEx_helpers.charval(-1) == ''


def test_check_json():
    # Check all conditions for the check_valid_json() function...
    data = {"identity": "123", "key": "1234", "type": "TYPE1"}
    assert KeyEx_helpers.check_valid_json(data) is True

    del data["key"]
    assert KeyEx_helpers.check_valid_json(data) is False

    del data["type"]
    assert KeyEx_helpers.check_valid_json(data) is False

    data.update({"key": "12345"})
    assert KeyEx_helpers.check_valid_json(data) is False

    del data["identity"]
    assert KeyEx_helpers.check_valid_json(data) is False

    data.update({"type": "TYPE7"})
    assert KeyEx_helpers.check_valid_json(data) is False

    del data["key"]
    assert KeyEx_helpers.check_valid_json(data) is False
