# This is a simulation of an LCD device... With the correct behaviours (but not actually driving a display).
import sys
sys.path.append('../')
sys.path.append('../../../')

import pySRUP
import hashlib
import logging
import coloredlogs
import traceback
import random
from threading import Timer

logger = logging.getLogger()
logger.setLevel(logging.INFO)
log_format_string = '%(asctime)s.%(msecs)03d \t [%(levelname)s] \t %(message)s'
coloredlogs.DEFAULT_LOG_FORMAT = log_format_string
coloredlogs.install(level='INFO')

# We'll hard-code the server for this simple device into the code…
server_id = "b9d077e223834cf6"
BASE_URL = "" # Must be a valid base URL...

FILENAME = "LCD_device.py"
joined = False

def on_join_refused():
    # This will be the handler which will be called, if we get a response message with a JOIN REFUSED status...
    logging.info("JOIN REFUSED message received...")
    client.send_SRUP_human_join()

def on_id_req():
    # Provide a function to return a string to provide the response to the ID request...
    # Here we'll just return the filename & a SHA-256 hash of the program code...
    with open(FILENAME, 'rb') as f:
        data = f.read()
    return "{} - SHA256 {}".format(FILENAME, hashlib.sha256(data).hexdigest())


def on_action(msg_action):
    if msg_action.sender_id == int(server_id, 16):
        if msg_action.action_id == 0x00:
            logging.info("ACTION: START")
        elif msg_action.action_id == 0xFF:
            logging.info("ACTION: STOP")
    else:
        logger.warning("Message not from server id {}".format(server_id))


def send_data(srup):
    global flag
    x = random.uniform(20, 25)
    srup.send_SRUP_Data(target_id=server_id, data_id="DATA", data=x)
    logging.info("Sending data – DATA = {}".format(x))
    flag = False


client = pySRUP.Client("lcd_dev.cfg", BASE_URL, device_type="LCD")
client.on_action(on_action)
client.on_join_refused(on_join_refused)
client.on_id_request(on_id_req)

# client.on_data(on_data)
# client.on_update(on_update)
# client.update_filename("update.data")

running = True
flag = False

with client:
    try:
        # Start by joining the server defined in the config...
        client.send_SRUP_simple_join()

        while running:
            if joined:
                if not flag:
                    y = random.randint(5, 15)
                    t = Timer(y, send_data, [client])
                    t.start()
                    flag = True

    except KeyboardInterrupt:
        logging.info("User requested exit - via Keyboard Interrupt...")
        if running and joined:
            t.cancel()
        client.save_settings()

    except Exception as e:
        logging.error(traceback.format_exc())
