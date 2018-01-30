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

## Building on Raspberry Pi

Note that a small change is required when building on Raspbian on a Raspberry Pi. A version of the `CMakeLists.txt` file with the neccessary changes is included as `CMakeLists.rpi.txt`; the original `CMakeLists.txt` should be removed, and this new version should be renamed as `CMakeLists.txt`.

To ensure all of the dependencies are in place, run:

`sudo apt-get install git make libboost-all-dev libssl-dev`


## Build process

Once all dependancies are satisfied, simply run `cmake .`, followed by running `make` in the usual way.

This will build the files.

## pySRUP

In order to use pySRUP - you will also need to have the `paho.mqtt`, and `pycryptdomex` Python libraries installed...

Use:

* `pip3 install --user paho.mqtt` 
* `pip3 install --user pycryptodomex`

If you want to use the Python unit tests – you'll also need `pytest` installed

* `pip3 install --user pytest`

To pass all of the unit tests – you'll also need to create an RSA key pair in the top-level directory.

* `openssl genrsa -out private_key.pem 2048`
* `openssl rsa -pubout -in private_key.pem -out public_key.pem`

## Notes

pySRUP has been built & tested on Linux (Fedora 26), MacOS (10.13), and Raspberry Pi (Rasbian Stretch Lite).

**Please note that neither SRUP_Lib or pySRUP have been tested on Windows. It should work; but I don't develop on Windows, so you're on your own…**

