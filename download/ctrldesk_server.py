"""CtrlDesk companion. Run on the laptop: python ctrldesk_server.py"""
import json
import os
import random
import secrets
import socket
import socketserver
import ssl
import sys
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pyautogui

PORT = 8765
PIN_FILE = Path.home() / ".ctrldesk_pin"
TLS_FILE = Path.home() / ".ctrldesk_tls.pem"
MOD = "command" if sys.platform == "darwin" else "ctrl"
WHEEL = 40 if sys.platform == "win32" else 1  # Windows scroll units are 1/120 of a notch
BUTTONS = {"left", "right", "middle"}
KEYS = set(pyautogui.KEYBOARD_KEYS)

pyautogui.PAUSE = 0
pyautogui.FAILSAFE = False  # a trackpad hits screen corners constantly

PIN = ""
jiggle_every = 0
jiggle_until = 0.0  # time.monotonic() deadline, 0 = forever
jiggle_phrase = ""  # non-empty: type it and erase it instead of moving the mouse
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
    global jiggle_every, jiggle_until, jiggle_phrase
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
        jiggle_phrase = str(m.get("phrase", ""))[:40] if jiggle_every else ""
        jiggle_wake.set()
    elif t == "nudge":
        nudge()
    else:
        raise ValueError(f"unknown command {t!r}")


def nudge():
    pyautogui.moveRel(1, 0)
    pyautogui.moveRel(-1, 0)


def type_and_erase(phrase):
    """Fake activity: type at a human pace, pause, then backspace it away."""
    for c in phrase:
        pyautogui.write(c)
        time.sleep(random.uniform(0.07, 0.22))
    time.sleep(random.uniform(0.5, 1.5))
    for _ in phrase:
        pyautogui.press("backspace")
        time.sleep(random.uniform(0.05, 0.14))


def jiggler():
    global jiggle_every
    while True:
        # random 70-130% spacing so it doesn't look robotic
        jiggle_wake.wait(jiggle_every * random.uniform(0.7, 1.3) if jiggle_every else None)
        jiggle_wake.clear()
        if jiggle_until and time.monotonic() > jiggle_until:
            jiggle_every = 0
        if jiggle_every:
            type_and_erase(jiggle_phrase) if jiggle_phrase else nudge()


class Client(socketserver.StreamRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        super().setup()

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

    def __init__(self, address, handler, tls):
        self.tls = tls
        super().__init__(address, handler)


def load_tls(path=TLS_FILE):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    if not path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CtrlDesk laptop")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        data = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(data)
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(path)
    return context, cert.fingerprint(hashes.SHA256()).hex()


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
    tls, fingerprint = load_tls()
    threading.Thread(target=jiggler, daemon=True).start()
    with Server(("0.0.0.0", PORT), Client, tls) as server:
        print(f"CtrlDesk ready (TLS)\n  Address: {lan_ip()}\n  PIN:     {PIN}")
        print(f"  Certificate SHA-256: {fingerprint}\n")
        print("Enter this fingerprint in the phone app before connecting. Never accept one supplied by another device.")
        print(f"Keep {TLS_FILE} private. Deleting it creates a new identity and requires pairing again.")
        print(f"Delete {PIN_FILE} for a new PIN. Ctrl+C to quit.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
