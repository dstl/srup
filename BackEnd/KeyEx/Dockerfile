FROM python:3.8.1-slim-buster

RUN python3 -m pip install --upgrade pip

COPY requirements.txt /
RUN python3 -m pip install -r /requirements.txt
RUN python3 -m pip install gunicorn

COPY . /KeyEx-Server
WORKDIR /KeyEx-Server

ENTRYPOINT ["./start.sh"]
