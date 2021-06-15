#!/bin/sh
gunicorn --chdir KeyEx-Server wsgi:application -w 2 --threads 2 -b 0.0.0.0:8000
