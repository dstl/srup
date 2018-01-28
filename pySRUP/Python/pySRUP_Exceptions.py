class SRUP_EXCEPTION (Exception):
    def __init__(self):
        self._msg = None

    def message(self):
        return self._msg


class SRUP_FETCHER_DIGEST_ERROR (SRUP_EXCEPTION):
    def __init__(self):
        super().__init__()
        self._msg = "Digest value does not match expected value"


class SRUP_FETCHER_SERVER_ERROR (SRUP_EXCEPTION):
    def __init__(self):
        super().__init__()
        self._msg = "Specified server could not be accessed"


class SRUP_FETCHER_LOCAL_FILE_IO_ERROR (SRUP_EXCEPTION):
    def __init__(self):
        super().__init__()
        self._msg = "The specified filename could not be created"


class SRUP_FETCHER_FILE_ERROR (SRUP_EXCEPTION):
    def __init__(self):
        super().__init__()
        self._msg = "The specified file could not be accessed"

