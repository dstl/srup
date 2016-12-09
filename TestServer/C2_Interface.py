import sys
sys.path.append('./thrift/gen-py')

from flask import Flask
from flask import request
from flask import jsonify
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

# For this simple demonstration we'll use a simple username / password cobination hardcoded into this API code...
# Obviously you wouldn't want to do this on a production system...
users = {"AJP": "Password_goes_here"}

from SRUP_Service import SRUP
from SRUP_Service.ttypes import TokenNotFoundException, SendInitException

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

# A simple check - whereas in a real system we'd need to use password hashing...
@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None

@app.route('/C2/api/v1.0/initiate/', methods=['POST'])
@auth.login_required
def Init():
    target = request.form.get("target")
    url = request.form.get("url")
    digest = request.form.get("digest")

    try:
        transport = TSocket.TSocket('localhost', 9090)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)

        client = SRUP.Client(protocol)
        transport.open()

        if target is None:
            return "Missing target", 400
        if url is None:
            return "Missing URL", 400
        if digest is None:
            return "Missing digest", 400

        token = client.SendInit(target, url, digest)

        transport.close()

        if token != "":
            return token, 201
        else:
            return "", 500

    except TokenNotFoundException:
        print ("Token not found")

    except TTransport.TTransportException:
        print ("Error starting client")

    except Thrift.TException, e:
        print ("Error: %s" % e)


@app.route('/C2/api/v1.0/response/<token>', methods=['GET'])
@auth.login_required
def get_resp(token):
    try:
        transport = TSocket.TSocket('localhost', 9090)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)

        client = SRUP.Client(protocol)
        transport.open()

        resp = client.GetResp(token)

        transport.close()

        if resp == 0:
            return jsonify(response=resp, message="SRUP_UPDATE_SUCCESS")
        elif resp == -1:
            return jsonify(response=resp, message="SRUP_UPDATE_FAIL_DIGEST")
        elif resp == -2:
            return jsonify(response=resp, message="SRUP_UPDATE_FAIL_FILE")
        elif resp == -3:
            return jsonify(response=resp, message="SRUP_UPDATE_FAIL_SERVER")

    except TokenNotFoundException:
        return "Invalid token", 400

    except TTransport.TTransportException:
        print ("Error starting client")

    except Thrift.TException, e:
        print ("Error: %s" % e)


@app.route('/C2/api/v1.0/activate/', methods=['POST'])
@auth.login_required
def doAct():
    token = request.form.get("token")
    try:
        transport = TSocket.TSocket('localhost', 9090)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)

        client = SRUP.Client(protocol)
        transport.open()

        rv = client.SendActivate(token)
        transport.close()

        if rv:
            return "Activation sent ok", 200
        else:
            return "Invalid token", 400

    except TokenNotFoundException:
        print ("Token not found")

    except TTransport.TTransportException:
        print ("Error starting client")

    except Thrift.TException, e:
        print ("Error: %s" % e)

if __name__ == '__main__':
    app.run()
