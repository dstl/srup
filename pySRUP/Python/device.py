import RPi.GPIO as GPIO
import time
import pySRUP
import os
import sys
import shutil

FILENAME = "device.py"
DELAY = 0.75
LED_STATE = False
auth = ("", "")


def led_setup():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(14, GPIO.OUT)
    GPIO.setup(24, GPIO.OUT)
    GPIO.setup(7, GPIO.OUT)
    GPIO.setup(12, GPIO.OUT)
    GPIO.setup(20, GPIO.OUT)
    GPIO.output(14, GPIO.LOW)
    GPIO.output(24, GPIO.LOW)
    GPIO.output(7, GPIO.LOW)
    GPIO.output(12, GPIO.LOW)
    GPIO.output(20, GPIO.LOW)


def toggle(state):
    if not state:
        GPIO.output(24, GPIO.HIGH)
        return True
    else:
        GPIO.output(24, GPIO.LOW)
        return False


def switch():
    GPIO.output(20, GPIO.HIGH)
    time.sleep(DELAY)
    GPIO.output(20, GPIO.LOW)


def on_action(msg_action):
    global LED_STATE
    if msg_action.action_id == 0x00:
        LED_STATE = toggle(LED_STATE)

    elif msg_action.action_id == 0xFF:
        switch()


def on_data(msg_data):
    global DELAY
    if msg_data.data_id == "Delay":
        DELAY = msg_data.double_data


def on_update(filename):
    # If we get here the update process has been carried out okay behind the scenes; and we have just received a
    # "go" signal - in which case we need to restart ourselves...
    # But first we need to copy the file to overwrite this one...
    shutil.copy(filename, *sys.argv)
    python = sys.executable
    os.execl(python, python, *sys.argv)


client = pySRUP.Client("device.cfg", "https://example.com")
client.on_action(on_action)
client.on_data(on_data)
client.on_update(on_update)
client.update_filename("update.data")
client.update_fetch_auth(auth)

led_setup()

with client:
    try:
        while 1:
            GPIO.output(14, GPIO.HIGH)
            time.sleep(0.5)
            GPIO.output(14, GPIO.LOW)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nExiting...\n")
        GPIO.cleanup()
