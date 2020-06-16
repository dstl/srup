from flask import Flask, render_template, redirect, url_for, flash, request
from flask_nav import Nav
from flask_nav.elements import Navbar, View
from flask_bootstrap import Bootstrap
from io import BytesIO
import base64
import time
from flask_moment import Moment
from datetime import datetime
import form_classes
import pictogram
import uuid
import logging
import logging.handlers
import atexit
import pygal

import sys
# Now import pySRUP...
sys.path.append('../')
sys.path.append('../../../')
import pySRUP

LOG_FILE = "web_c2.log"

nav = Nav()
app = Flask(__name__)
app.config['SECRET_KEY'] = '' # flask debug key...
bootstrap = Bootstrap(app)
nav.init_app(app)
moment = Moment(app)

C2_Server = pySRUP.Server("config.cfg")

devices = []
device_status = {}
device_data = {}
device_type = {}

DEVICE_START = 0x00
DEVICE_STOP = 0xFF

# We might need to update these to a dictionaries at some point, to handle multiple simultaneous (human/machine)
# moderated joins...
joinPending = False
pending_device = ""
validation_value = ""

# Load the word list...
with open('longwords.txt', 'r') as f:
    word_list = f.read().splitlines()


def wordlist(data):
    bits_list = []
    words = []
    mask = 0x1FFF
    int_value = data
    for i in range(9):
        bits_list.append((int_value >> (13 * i)) & mask)

    bits_list.append(int_value >> 117)

    # Now we have the word list - we need to pad the final block to 13-bits...
    bits_list[9] = bits_list[9] << 2
    for i in range(0, len(bits_list), 2):
        t = [word_list[bits_list[i]], word_list[bits_list[i+1]]]
        words.append(t)
    return words


def on_join(joining_device):
    global C2_Server
    global devices
    global joinPending
    global validation_value

    # The workflow here is to first check the type of the device requesting to join...
    dev_type = C2_Server.device_types[joining_device]

    # ... now we have it; we'll use simple decision logic to accept only devices of types "simple" and "TEST"
    if dev_type == 'simple' or dev_type == 'TEST' or dev_type == 'OBSERVER_DEMO':
        device_type[joining_device] = dev_type
        if joining_device not in devices:
            devices.append(joining_device)
        if joining_device not in device_data:
            device_data[joining_device] = []
        C2_Server.accept_join(joining_device, ID_req=True)

    elif dev_type == 'LCD' or dev_type == 'inky' or dev_type == 'HEX' or dev_type == 'OBS':
        # Send a response message - with a JOIN_REFUSED value...
        C2_Server.refuse_join(joining_device)
        # And do some other stuff to follow...??


def on_human_join(joining_device):
    global C2_Server
    global devices
    global joinPending
    global validation_value
    global pending_device

    # The workflow here is to first check the type of the device requesting to join...
    dev_type = C2_Server.device_types[joining_device]

    # ... now we have it; we'll use simple decision logic to *reject* types "simple" and "TEST"
    if dev_type == 'LCD' or dev_type == 'inky' or dev_type == 'HEX':
        # We'll use the joinPending flag to signal that a join that won't be automatically handled
        # has been requested.
        joinPending = True
        pending_device = joining_device
        validation_value = C2_Server.send_human_join_response(joining_device)
    else:
        # If it's not a device type we're expecting – we'll reject it…
        logging.warning("Automatically rejected request from unknown or unsuitable device type ({})"
                        .format(device_type[joining_device]))
        C2_Server.fail_join(joining_device)


def on_observed_join(joining_device, observer):
    global C2_Server
    global devices
    global joinPending
    global validation_value
    global pending_device

    # The workflow here is to first check the type of the device requesting to join...
    dev_type = C2_Server.device_types[joining_device]

    # ... now we have it; we'll use simple decision logic to only accept requests from *OBS* type devices
    if dev_type == 'OBS':
        # We'll use the joinPending flag to signal that a join that won't be automatically handled
        # has been requested.
        joinPending = True
        pending_device = joining_device

        validation_value = C2_Server.send_observed_join_response(joining_device)
        C2_Server.send_observation_request(observer, joining_device, validation_value)
    else:
        # If it's not a device type we're expecting – we'll reject it…
        logging.warning("Automatically rejected request from unknown or unsuitable device type ({})"
                        .format(device_type[joining_device]))
        C2_Server.fail_join(joining_device)


def on_observed_join_succeed():
    global joinPending
    global pending_device
    global devices

    device = pending_device
    dev_type = C2_Server.device_types[device]

    if device not in devices:
        device_type[device] = dev_type
        devices.append(device)
        if device not in device_data:
            device_data[device] = []
    joinPending = False
    C2_Server.accept_join(device, True)


def on_observed_join_invalid():
    # The observation was invalid; so remove the device, and signal back.
    global joinPending
    global pending_device

    device = pending_device
    joinPending = False
    C2_Server.fail_join(device)


def on_observed_join_fail():
    # The observation failed; so retry.
    global pending_device
    C2_Server.refuse_join(pending_device)


def on_data(msg_data):
    global device_status
    global device_data
    if msg_data.data_id == "IDENTIFICATION_RESPONSE":
        logging.info("ID data: {}".format(msg_data.bytes_data))
        device = hex(msg_data.sender_id).lstrip('0x')
        device_status[device] = {'status': msg_data.bytes_data}
    elif msg_data.data_id == "DATA":
        logging.info("ID data: {}".format(msg_data.double_data))
        device = hex(msg_data.sender_id).lstrip('0x')
        if device in device_data:
            device_data[device].append((datetime.now(), msg_data.double_data))
        else:
            device_data[device] = [(datetime.now(), msg_data.double_data)]


def serve_pil_image(pil_img):
    img_io = BytesIO()
    pil_img.save(img_io, 'PNG')
    img_io.seek(0)
    return base64.b64encode(img_io.getvalue()).decode('ascii')


@nav.navigation()
def site_navbar():
    global joinPending
    if joinPending:
        return Navbar(
            'IoT Lab',
            View('Overview', 'index'),
            View('Devices', 'device_list_page'),
            View('Join', 'join_page'),
            View('Action', 'action_page')
        )
    else:
        return Navbar(
            'IoT Lab',
            View('Overview', 'index'),
            View('Devices', 'device_list_page'),
            View('Action', 'action_page')
        )


@app.template_filter('ctime')
def timectime(s):
    return time.ctime(s)


@app.route('/')
def index():
    return render_template('index.html', server_id=server_id, current_time=datetime.utcnow())


@app.route('/devices')
def device_list_page():
    global device_status
    global device_type
    global devices
    return render_template('devices.html',
                           server=server_id, devices=devices, device_status=device_status, device_type=device_type)


@app.route('/graph/')
def graph_page():
    device = request.args.get('device')
    if device in device_data:
        try:
            graph = pygal.DateTimeLine(x_label_rotation=45,
                                       x_value_formatter=lambda dt: dt.strftime('%-d %b %y - %H:%M:%S'),
                                       show_legend=False,
                                       stroke_style={'width': 3},
                                       dots_size=4,
                                       range=(15.0, 30.0))
            graph.title = 'Device Data:'
            sorted_data = sorted(device_data[device])
            graph.add(device, sorted_data)
            graph_data = graph.render_data_uri()
            return render_template("graph.html", device=device, graph_data=graph_data)
        except Exception as e:
            return str(e)
    else:
        return render_template("graph.html", device=device, graph_data=None)


@app.route('/join', methods=['GET', 'POST'])
def join_page():
    global joinPending
    global validation_value
    global pending_device
    j_form = form_classes.JoinForm()
    pic1 = pictogram.Monochrome(400)
    pic2 = pictogram.Color(400)

    dev_type = C2_Server.device_types[pending_device]

    if j_form.validate_on_submit():
        if j_form.accept.data:
            # TODO: Do accept join stuff…

            if pending_device not in devices:
                device_type[pending_device] = dev_type
                devices.append(pending_device)
                if pending_device not in device_data:
                    device_data[pending_device] = []
            joinPending = False
            C2_Server.accept_join(pending_device, ID_req=True)
            print("JOINED")

        elif j_form.reject.data:
            # TODO: Do reject join stuff…
            print("REJECTED")
            C2_Server.fail_join(pending_device)
            joinPending = False
        return redirect(url_for('index'))

    else:
        if dev_type == "HEX":
            i1 = None
            i2 = None
            wl = None
            hc = validation_value
        elif dev_type == "LCD":
            i1 = None
            i2 = serve_pil_image(pic2.plot_uuid(int(validation_value, 16)))
            wl = None
            hc = None
        elif dev_type == "inky":
            i1 = None
            i2 = None
            wl = wordlist(int(validation_value, 16))
            hc = None
        else:
            i1 = serve_pil_image(pic1.plot_uuid(int(validation_value, 16)))
            i2 = None
            wl = None
            hc = validation_value

        return render_template('join_page.html', image1=i1, image2=i2, hex_code=hc, wordlist=wl,
                               device=pending_device, dev_type=dev_type, form=j_form)


@app.route('/action', methods=['GET', 'POST'])
def action_page():
    form = form_classes.ActionForm()
    form.device.choices = [(device, device) for device in devices]
    if form.validate_on_submit():
        flash("Action Sent – Device: {}, Action: {}".format(form.device.data, form.action_type.data))
        if form.action_type.data == "START":
            C2_Server.send_SRUP_Action(target_id=form.device.data, action_id=DEVICE_START)
        elif form.action_type.data == "STOP":
            C2_Server.send_SRUP_Action(target_id=form.device.data, action_id=DEVICE_STOP)
        return redirect(url_for('index'))
    return render_template('action.html', form=form)


# <editor-fold desc="For completeness – add 404 / 500 pages...">

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
# </editor-fold>


# For a clean shutdown we must save state...
def shutdown():
    global C2_Server
    print("Shutdown")
    C2_Server.save_settings()


if __name__ == '__main__':
    atexit.register(shutdown)

    with C2_Server:
        server_id = C2_Server.id
        C2_Server.on_data(on_data)
        C2_Server.on_join_request(on_join)
        C2_Server.on_human_join_request(on_human_join)
        C2_Server.on_observed_join_request(on_observed_join)
        C2_Server.on_observed_join_succeed(on_observed_join_succeed)
        C2_Server.on_observed_join_invalid(on_observed_join_invalid)
        C2_Server.on_observed_join_fail(on_observed_join_fail)
        app.run(host="0.0.0.0")
