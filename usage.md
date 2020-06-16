# How to use SRUP & the example code provided…

The purpose of this file, is to introduce the SRUP example code that is contained within this repository; and show you how to get a demo application up and running.

For build instructions – please see: build.md



## SRUP & pySRUP

Running `cmake` will build the SRUP C++ Library (`libSRUP_Lib`); and then use this to build the static `pySRUPLib` library for use with Python. The C++ files used to generate this can be found within the `pySRUP` subfolder (e.g. `.../srup/pySRUP`).

The files within the `.../srup/pySRUP/Python` folder contains the Python classes to implement the pySRUP module. It is expected that this will be released via the Python Package Index (PyPI) in due course, to permit direct installation of pySRUP – rather than requiring Python users to build from the C++ source.



## KeyEx Service

The backend key service used by pySRUP is implemented via the Python files found in the `KeyEx` subfolder. In a production environment this should be running on an Internet-facing web server (using a wsgi gateway application server, such as gunicorn). For development purposes it may be run locally, using the integrated development web server bundled with the Python Flask library.



## WebC2

An example implementation of a web C2 server is also included; and can be found in the `.../srup/pySRUP/Python/WebC2` folder. The application's main file is `web_c2.py`. An example config file is included (`config.cfg`); as is a simple example software-only client. 



## Hardware

The `.../srup/pySRUP/Python/Hardware` folder contains the source code for two example hardware devices; along with a short description of the hardware used.