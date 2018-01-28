class KeyExReturn:
    def __init__(self):
        self._status_code = None
        self._msg = None

    def __call__(self):
        return self._msg, self._status_code

    def status_code(self):
        return self._status_code

    def message(self):
        return self._msg


class OK(KeyExReturn):
    def __init__(self, data):
        super().__init__()
        self._status_code = 200
        self._msg = data


class Success(KeyExReturn):
    def __init__(self, data):
        super().__init__()
        self._status_code = 201
        self._msg = data


class NonUniqueKey(KeyExReturn):
    def __init__(self, dev_id):
        super().__init__()
        self._status_code = 400
        self._msg = "Device ID {} already exists; and could not be added.".format(dev_id)


class Forbidden(KeyExReturn):
    def __init__(self):
        super().__init__()
        self._status_code = 403
        self._msg = "Server is inactive and not accepting new registration requests."


class MissingJSON(KeyExReturn):
    def __init__(self, data):
        super().__init__()
        self._status_code = 400
        self._msg = "Missing or invalid values in JSON data received:\n{}".format(data)


class BadJSON(KeyExReturn):
    def __init__(self, data):
        super().__init__()
        self._status_code = 400
        self._msg = "Malformed JSON data received:\n{}".format(data)


class DatabaseError(KeyExReturn):
    def __init__(self, data):
        super().__init__()
        self._status_code = 500
        self._msg = "A database error occurred - {}".format(data)


class DatabaseConnectionError(KeyExReturn):
    def __init__(self):
        super().__init__()
        self._status_code = 500
        self._msg = "An internal database error has occurred..."


class SignatureVerificationError(KeyExReturn):
    def __init__(self):
        super().__init__()
        self._status_code = 400
        self._msg = "The signature did not verify"


class CSRVerificationError(KeyExReturn):
    def __init__(self):
        super().__init__()
        self._status_code = 400
        self._msg = "The CSR data did not verify"
