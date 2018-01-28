# Import the necessary packages
import pySRUP
from cursesmenu import *
from cursesmenu.items import *


# Define settings for the software update.
url_a = "https://example.com/SRUP/device_a.py"
digest_a = "28097c1d4598115f86cc575edac4ee1879a73a2ee84b36d274218587ef36c37c"

url_b = "https://example.com/SRUP/device_b.py"
digest_b = "cd87659f55c6eb762c2a9134623f81a8c41293d93eba656340182580e48162a0"

target_id = "4fee7a2cae344c12"  # - hardware
# target_id = "4c3147697e474b95"  # - test software


def on_update_success(token):
    # We'll automatically activate this time...
    server.send_SRUP_Activate(target_id, token)


def send_action(server, target_id, action_id):
    server.send_SRUP_Action(target_id, action_id)

server = pySRUP.Server("server.cfg")

server.on_update_success(on_update_success)

with server:
    menu = CursesMenu("SRUP Server", subtitle="Secure Remote Update Protocol C2 Server")
    sub_menu = CursesMenu("Update Menu", subtitle="Send Update Commands")

    # A FunctionItem runs a Python function when selected
    toggle_item = FunctionItem("Send Toggle", send_action, [server, target_id, 0x00])
    switch_item = FunctionItem("Send Switch", send_action, [server, target_id, 0xFF])
    long_item = FunctionItem("Send Delay = 1.50 s", server.send_SRUP_Data, [target_id, "Delay", 1.50])
    short_item = FunctionItem("Send Delay = 0.75 s", server.send_SRUP_Data, [target_id, "Delay", 0.75])

    u1 = FunctionItem("Send A", server.send_SRUP_Initiate, [target_id, url_a, digest_a])
    u2 = FunctionItem("Send B", server.send_SRUP_Initiate, [target_id, url_b, digest_b])

    sub_menu.append_item(u1)
    sub_menu.append_item(u2)

    submenu_item = SubmenuItem("Update Menu", sub_menu, menu)

    menu.append_item(toggle_item)
    menu.append_item(switch_item)
    menu.append_item(long_item)
    menu.append_item(short_item)
    menu.append_item(submenu_item)
    menu.show()
    server.save_settings()

