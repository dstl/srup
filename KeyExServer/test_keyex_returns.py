import KeyExReturn


def test_http_success_return():
    # Test KeyExReturn.Success()
    data = "{'Test':True, 'Name':'Test'}"
    okay = KeyExReturn.Success(data)
    status_code = 201
    assert okay.status_code() == status_code
    assert okay.message() == data
    assert okay() == (data, status_code)


def test_http_non_unique_key_return():
    # Test KeyExReturn.NonUniqueKey()
    dev_id = "ABC"
    data = "Device ID {} already exists; and could not be added.".format(dev_id)
    status_code = 400

    non_unique = KeyExReturn.NonUniqueKey(dev_id)
    assert non_unique.status_code() == status_code
    assert non_unique.message() == data
    assert non_unique() == (data, status_code)


def test_http_forbidden():
    # Test KeyExReturn.Forbidden()
    status_code = 403
    data = "Server is inactive and not accepting new registration requests."
    forbidden = KeyExReturn.Forbidden()
    assert forbidden.status_code() == status_code
    assert forbidden.message() == data
    assert forbidden() == (data, status_code)


def test_http_missing_json():
    # Test KeyExReturn.MissingJSON()
    status_code = 400
    json_data = '{"identity":"12345", "key":"1234567"}'
    data = "Missing or invalid values in JSON data received:\n{}".format(json_data)
    missing = KeyExReturn.MissingJSON(json_data)
    assert missing.status_code() == status_code
    assert missing.message() == data
    assert missing() == (data, status_code)


def test_http_bad_json():
    # Test KeyExReturn.BadJSON()
    status_code = 400
    text = "Something is wrong with the data..."
    data = "Malformed JSON data received:\n{}".format(text)
    bad = KeyExReturn.BadJSON(text)
    assert bad.status_code() == status_code
    assert bad.message() == data
    assert bad() == (data, status_code)


def test_http_database_error():
    # Test KeyExReturn.DatabaseError()
    status_code = 500
    text = "Something bad happened..."
    data = "A database error occurred - {}".format(text)
    db = KeyExReturn.DatabaseError(text)
    assert db.status_code() == status_code
    assert db.message() == data
    assert db() == (data, status_code)


def test_http_database_connection_error():
    # Test KeyExReturn.DatabaseConnectionError()
    status_code = 500
    data = "An internal database error has occurred..."
    db = KeyExReturn.DatabaseConnectionError()
    assert db.status_code() == status_code
    assert db.message() == data
    assert db() == (data, status_code)

