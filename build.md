# Building SRUP

Both libSRUP & the pySRUP Python library are in development and as such the process to build them is slightly less straightforward than it is intended to eventually be the case. At present both libraries much be built from source; and this requires the system have have the following dependancies installed:

* Python 3.6
* Boost Python3
* Boost Logs
* Python Libs 3.6
* OpenSSL 1.0.2 (or higher)
* OpenSSL / libcrypto static libraries
* cmake 3.6 (or higher)


If you want to run the C++ unit tests you'll need to install the google test suite into the `Test/lib` directory…  Otherwise you should comment out the test section of `CMakeLists.txt`

## Build process

Once all dependancies are satisfied, simply run `cmake .`, followed by running `make` in the usual way.

This will build the files.

## Notes

pySRUP has been built & tested on Linux (Fedora 26), MacOS (10.13), and Raspberry Pi (Rasbian).

**Please note that neither SRUP_Lib or pySRUP have been tested on Windows. It should work; but I don't develop on Windows, so you're on your own…**

