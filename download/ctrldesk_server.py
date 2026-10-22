"""CtrlDesk companion. Run on the laptop: python ctrldesk_server.py"""
import json
import secrets
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

import pyautogui

PORT = 8765
PIN_FILE = Path.home() / ".ctrldesk_pin"
MOD = "command" if sys.platform == "darwin" else "ctrl"
WHEEL = 40 if sys.platform == "win32" else 1  # Windows scroll units are 1/120 of a notch
BUTTONS = {"left", "right", "middle"}
KEYS = set(pyautogui.KEYBOARD_KEYS)

pyautogui.PAUSE = 0
pyautogui.FAILSAFE = False  # a trackpad hits screen corners constantly

PIN = ""
jiggle_every = 0
jiggle_until = 0.0  # time.monotonic() deadline, 0 = forever
jiggle_wake = threading.Event()
fail_lock = threading.Lock()


def key(k):
    k = MOD if k == "mod" else k
    if k not in KEYS:
        raise ValueError(f"unknown key {k!r}")
    return k


def button(b):
    if b not in BUTTONS:
        raise ValueError(f"unknown button {b!r}")
    return b


def run(m):
    global jiggle_every, jiggle_until
    t = m["t"]
    if t == "move":
        pyautogui.moveRel(int(m["dx"]), int(m["dy"]))
    elif t == "click":
        pyautogui.click(button=button(m["b"]))
    elif t == "down":
        pyautogui.mouseDown(button=button(m["b"]))
    elif t == "up":
        pyautogui.mouseUp(button=button(m["b"]))
    elif t == "scroll":
        pyautogui.scroll(int(m["dy"]) * WHEEL)
    elif t == "type":
        pyautogui.write(str(m["text"]))  # ponytail: ASCII only; unicode needs a clipboard-paste path
    elif t == "key":
        pyautogui.press(key(m["k"]), presses=max(1, min(int(m.get("n", 1)), 500)))
    elif t == "hotkey":
        pyautogui.hotkey(*[key(k) for k in m["keys"]])
    elif t == "jiggle":
        jiggle_every = max(5, int(m["every"])) if int(m["every"]) else 0
        minutes = int(m.get("minutes", 0))
        jiggle_until = time.monotonic() + minutes * 60 if jiggle_every and minutes else 0
        jiggle_wake.set()
    elif t == "nudge":
        nudge()
    else:
        raise ValueError(f"unknown command {t!r}")


def nudge():
    pyautogui.moveRel(1, 0)
    pyautogui.moveRel(-1, 0)


def jiggler():
    global jiggle_every
    while True:
        jiggle_wake.wait(jiggle_every or None)
        jiggle_wake.clear()
        if jiggle_until and time.monotonic() > jiggle_until:
            jiggle_every = 0
        if jiggle_every:
            nudge()


class Client(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            pin = str(json.loads(self.rfile.readline(256))["pin"])
        except (OSError, ValueError, KeyError, TypeError):
            return
        if not secrets.compare_digest(pin.encode(), PIN.encode()):
            # ponytail: serialized 2s penalty caps guessing at ~0.5/s across all connections (LAN only)
            with fail_lock:
                time.sleep(2)
            self.wfile.write(b'{"ok": false}\n')
            return
        self.request.settimeout(None)
        self.wfile.write(json.dumps({"ok": True, "jiggle": jiggle_every}).encode() + b"\n")
        print(f"Connected: {self.client_address[0]}")
        try:
            for line in self.rfile:
                try:
                    run(json.loads(line))
                except Exception as e:
                    print(f"Ignored bad command: {e}")
        except OSError:
            pass
        finally:
            pyautogui.mouseUp()  # never leave a button stuck down
            print("Disconnected")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def lan_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def load_pin():
    if not PIN_FILE.exists():
        PIN_FILE.write_text(f"{secrets.randbelow(10**6):06d}")
    return PIN_FILE.read_text().strip()


if __name__ == "__main__":
    PIN = load_pin()
    threading.Thread(target=jiggler, daemon=True).start()
    with Server(("0.0.0.0", PORT), Client) as server:
        print(f"CtrlDesk ready\n  Address: {lan_ip()}\n  PIN:     {PIN}\n")
        print(f"Delete {PIN_FILE} for a new PIN. Ctrl+C to quit.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
