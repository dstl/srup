import db_return


def test_db_connection_created():
    # Test db_return.DatabaseConnectionCreated()
    x = object
    db = db_return.DatabaseConnectionCreated(x)
    assert db.connection() == x
    assert db.success() is True
    assert db.type() == "Connected"
    assert db.message() is None


def test_db_action_success():
    # Test db_return.DatabaseSuccess()
    db = db_return.DatabaseSuccess()
    assert db.connection() is None
    assert db.success() is True
    assert db.type() == "Success"
    assert db.message() is None


def test_db_error_non_unique_key():
    # Test db_return.DatabaseErrorNonUniqueKey()
    db = db_return.DatabaseErrorNonUniqueKey()
    assert db.connection() is None
    assert db.success() is not True
    assert db.type() == "NonUnique"
    assert db.message() == "Requested Database Key was not unique."


def test_db_error_generic():
    # Test db_return.DatabaseErrorGeneric()
    text = "Test message"
    db = db_return.DatabaseErrorGeneric(text)
    assert db.connection() is None
    assert db.success() is not True
    assert db.type() == "GenericError"
    assert db.message() == text


def test_db_error_not_connected():
    # Test db_return.DatabaseErrorNotConnected()
    text = "Test message"
    db = db_return.DatabaseErrorNotConnected(text)
    assert db.connection() is None
    assert db.success() is not True
    assert db.type() == "NotConnected"
    assert db.message() == text
