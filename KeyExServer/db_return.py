# We will implement our own bespoke class hierarchy for database return...
# There are other ways to do this; but we don't need too much complexity here - just a way to return the outcome
# of an externally-called database operation


class DatabaseReturn:
    def __init__(self):
        self._success = None
        self._msg = None
        self._type = None
        self._connection = None

    def message(self):
        return self._msg

    def type(self):
        return self._type

    def success(self):
        return self._success

    def connection(self):
        return self._connection


class DatabaseConnectionCreated(DatabaseReturn):
    def __init__(self, connection):
        super().__init__()
        self._success = True
        self._type = "Connected"
        self._connection = connection


class DatabaseSuccess(DatabaseReturn):
    def __init__(self):
        super().__init__()
        self._type = "Success"
        self._success = True


class DatabaseErrorNonUniqueKey(DatabaseReturn):
    def __init__(self):
        super().__init__()
        self._success = False
        self._type = "NonUnique"
        self._msg = "Requested Database Key was not unique."


class DatabaseErrorGeneric(DatabaseReturn):
    def __init__(self, error):
        super().__init__()
        self._success = False
        self._type = "GenericError"
        self._msg = error


class DatabaseErrorNotConnected(DatabaseReturn):
    def __init__(self, error):
        super().__init__()
        self._success = False
        self._type = "NotConnected"
        self._msg = error

