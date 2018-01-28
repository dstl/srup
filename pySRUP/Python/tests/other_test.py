import sys
sys.path.append('../../.../')

import pytest
import pySRUPLib

# Other tests of the library that don't fit anywhere else...


def test_version():
    """Test the version returns the current version"""
    x = pySRUPLib.SRUP_Generic()
    assert x.version == pySRUPLib.__version()
