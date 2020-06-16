import sys
sys.path.append('../')
sys.path.append('../../../')

import pySRUP
import hashlib
import logging
import coloredlogs
import traceback
import random
import pg

logger = logging.getLogger()
logger.setLevel(logging.INFO)
log_format_string = '%(asctime)s.%(msecs)03d \t [%(levelname)s] \t %(message)s'
coloredlogs.DEFAULT_LOG_FORMAT = log_format_string
coloredlogs.install(level='INFO')

lcd = pg.pictogram()

# We'll hard-code the server for this simple device into the code…
server_id = "b9d077e223834cf6"
BASE_URL = "" # Must be a valid base URL
FILENAME = "sw2.py"
flag = False


def on_action(msg_action):
    if msg_action.sender_id == int(server_id, 16):
        if msg_action.action_id == 0x00:
            logging.info("ACTION: START")
            lcd.fill_screen((0,255,0))
        elif msg_action.action_id == 0xFF:
            logging.info("ACTION: STOP")
            lcd.fill_screen((0,0,255))
    else:
        logger.warning("Message not from server id {}".format(server_id))


def on_id_req():
    # Provide a function to return a string to provide the response to the ID request...
    # Here we'll just return the filename & a SHA-256 hash of the program code...
    with open(FILENAME, 'rb') as f:
        data = f.read()
    return "{} - SHA256 {}".format(FILENAME, hashlib.sha256(data).hexdigest())


def send_data(srup):
    global flag
    x = random.uniform(20, 25)
    srup.send_SRUP_Data(target_id=server_id, data_id="DATA", data=x)
    logging.info("Sending data – DATA = {}".format(x))
    flag = True


def on_join_refused():
    client.send_SRUP_human_join()
    logger.info("Sending Human Join Request")

def on_join_failed():
    logger.warning("Join Failed – Rejected by Server")
    lcd.fill_screen((255,0,0))

def on_human_join_response(secret_key):
    logging.info("Secret Key recieved – {}".format(secret_key))
    lcd.draw_box(int(secret_key, 16))

def on_join_succeed():
    logger.info("Join Accepted")
    lcd.fill_screen((255,255,0))

client = pySRUP.Client("sw2.cfg", BASE_URL, device_type="LCD")
client.on_action(on_action)
client.on_id_request(on_id_req)
client.on_join_refused(on_join_refused)
client.on_join_failed(on_join_failed)
client.on_human_join_response(on_human_join_response)
client.on_join_succeed(on_join_succeed)

# client.on_data(on_data)
# client.on_update(on_update)
# client.update_filename("update.data")

running = True

with client:
    try:
        # Start by joining the server defined in the config...
        client.send_SRUP_simple_join()

        while running:
            pass

    except KeyboardInterrupt:
        logging.info("User requested exit - via Keyboard Interrupt...")
        client.save_settings()

    except Exception as e:
        logging.error(traceback.format_exc())
