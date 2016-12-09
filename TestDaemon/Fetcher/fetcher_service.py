import sys 
sys.path.append('gen-py')

from fetcher import Fetcher
from fetcher.ttypes import *
from fetcher.constants import *

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

import requests
import hashlib
import logging
import coloredlogs
import socket
import subprocess

downloaded_file = "device.py"
python_command = "python3"
kill_command = "pkill"
kill_args = "-f"
execute_path = "./execute/"
i_auth = ('AJP', 'password_goes_here')

# Setup the logging...
logger = logging.getLogger()
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t\t%(message)s')
logfile = logging.FileHandler('fetcher_service_log')
logfile.setLevel(logging.INFO)
logfile.setFormatter(formatter)
logger.addHandler(logfile)
coloredlogs.DEFAULT_FIELD_STYLES['levelname']={'color': 'white'}
coloredlogs.DEFAULT_LOG_FORMAT = '%(asctime)s\t%(levelname)s\t\t%(message)s'
coloredlogs.install(level='INFO')

# Setup some "constants"...
FETCHER_RETURN_OK = 0
FETCHER_RETURN_DIGEST_ERROR = 1
FETCHER_RETURN_SERVER_ERROR = 2
FETCHER_RETURN_FILE_ERROR = 3

def hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()

class FetcherHandler (Fetcher.Iface):
        def __init__(self):
             # Initialization...
             pass

        def FETCH_FROM_URL (self, url, digest):
                try:
                    r = requests.get(url, auth=i_auth)
                    r.raise_for_status()

                    open(downloaded_file , 'wb').write(r.content)

                    # DEBUG CODE...
                    logger.info("File downloaded...")

                    with open(downloaded_file, 'rb') as f:
                        d = hashfile(f, hashlib.sha256())

                    if (d == digest):
                        return FETCHER_RETURN_OK
                    else:
                        return FETCHER_RETURN_DIGEST_ERROR

                except requests.ConnectionError:
                    logger.error("FETCHER_RETURN_SERVER_ERROR")
                    return FETCHER_RETURN_SERVER_ERROR

                except requests.HTTPError:
                    if (r.status_code == 404):
                        logger.error("FETCHER_RETURN_FILE_ERROR")
                        return FETCHER_RETURN_FILE_ERROR
                    else:
                        # If it's not a 404 - then we'll assume the server is bad...
                        # Obviously we could add an extra SRUP error-code for all / any HTTP errors we might get...
                        logger.error("FETCHER_RETURN_SERVER_ERROR")
                        return FETCHER_RETURN_SERVER_ERROR

        def START_STOP (self):
            logger.info("Executor beginning Start / Stop...")
            if subprocess.call([kill_command, kill_args, downloaded_file]) == 0:
                logger.info("Old Process halted")
                if subprocess.call(["cp", downloaded_file, execute_path]) == 0:
                    logger.info("File operation complete")
                    # Copy the file to the directory we execute it from...
                    # This probably isn't the most Pythonic way to do this!
                    # (Note that we don't need to worry about deleting the file first - as cp will overwrite)

                    p=subprocess.Popen([python_command, execute_path + downloaded_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    logger.info("New process started")
                    return True
                else:
                    return False
            else:
                return False


# Main program...
try:
    handler = FetcherHandler()
    processor = Fetcher.Processor(handler)
    transport = TSocket.TServerSocket(port=9091)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

    server.serve()

except socket.error:
    logger.error("Error starting Thrift Service")

except Thrift.TException, e:
    logger.error ("Thrift Exception" + e.error_description)
