"""CtrlDesk companion. Run on the laptop: python ctrldesk_server.py"""
import collections
import json
import os
import random
import secrets
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pyautogui

PORT = 8765
PIN_FILE = Path.home() / ".ctrldesk_pin"
TLS_FILE = Path.home() / ".ctrldesk_tls.pem"
MOD = "command" if sys.platform == "darwin" else "ctrl"
WHEEL = 120 if sys.platform == "win32" else 1  # one notch, same as Bluetooth
BUTTONS = {"left", "right", "middle"}
KEYS = set(pyautogui.KEYBOARD_KEYS)

pyautogui.PAUSE = 0
pyautogui.FAILSAFE = False  # a trackpad hits screen corners constantly

PIN = ""
jiggle_every = 0
jiggle_until = 0.0  # time.monotonic() deadline, 0 = forever
jiggle_phrase = ""  # non-empty: type it and erase it instead of moving the mouse
jiggle_wake = threading.Event()
input_lock = threading.RLock()
manual_lock = threading.Lock()
manual_waiters = 0
manual_cancel = threading.Event()
fail_lock = threading.Lock()
MAX_FAILS = 10  # wrong PINs from one device before that device is locked out
LOCKOUT_S = 15 * 60
GLOBAL_MAX_FAILS = 100  # wrong PINs from everyone within LOCKOUT_S before all new logins wait
sources = {}  # client address -> [wrong PINs, next attempt allowed at, locked until]
recent_fails = collections.deque()  # times of recent wrong PINs from anyone
global_locked_until = 0.0
MAX_CONNECTIONS = 8
MAX_UNAUTHED = 4  # of those, how many may still be logging in
AUTH_DEADLINE_S = 10  # the whole login (TLS handshake + PIN), however slowly a client sends
MAX_LINE = 64 * 1024  # longest command accepted after login


def key(k):
    k = MOD if k == "mod" else k
    if sys.platform == "darwin" and k == "win":
        k = "command"  # custom shortcuts saved with Win mean Cmd on a Mac
    if k not in KEYS:
        raise ValueError("unknown key")  # never echo client data into the log
    return k


def button(b):
    if b not in BUTTONS:
        raise ValueError("unknown button")
    return b


@contextmanager
def manual_input():
    global manual_waiters
    # Announce manual input before waiting, so the current cycle can erase and yield.
    with manual_lock:
        manual_waiters += 1
        manual_cancel.set()
    try:
        with input_lock:
            yield
    finally:
        with manual_lock:
            manual_waiters -= 1
            if not manual_waiters:
                manual_cancel.clear()


def run(m, pressed=None):
    global jiggle_every, jiggle_until, jiggle_phrase
    with manual_input():
        t = m["t"]
        if t == "move":
            pyautogui.moveRel(int(m["dx"]), int(m["dy"]))
        elif t == "click":
            pyautogui.click(button=button(m["b"]))
        elif t == "down":
            b = button(m["b"])
            pyautogui.mouseDown(button=b)
            if pressed is not None:
                pressed.add(b)
        elif t == "up":
            b = button(m["b"])
            pyautogui.mouseUp(button=b)
            if pressed is not None:
                pressed.discard(b)
        elif t == "scroll":
            pyautogui.scroll(int(m["dy"]) * WHEEL)
        elif t == "type":
            pyautogui.write(str(m["text"])[:2000])  # ponytail: ASCII only; unicode needs a clipboard-paste path
        elif t == "key":
            pyautogui.press(key(m["k"]), presses=max(1, min(int(m.get("n", 1)), 500)))
        elif t == "hotkey":
            pyautogui.hotkey(*[key(k) for k in m["keys"]])
        elif t == "jiggle":
            every = int(m["every"])
            minutes = int(m.get("minutes", 0))
            if (every != 0 and not 5 <= every <= 3600) or not 0 <= minutes <= 1440:
                raise ValueError("jiggle every must be 0 or 5..3600; minutes must be 0..1440")
            phrase = str(m.get("phrase", ""))[:40] if every else ""
            until = time.monotonic() + minutes * 60 if every and minutes else 0
            jiggle_every, jiggle_until, jiggle_phrase = every, until, phrase
            jiggle_wake.set()
        elif t == "nudge":
            nudge()
        else:
            raise ValueError("unknown command")


def nudge():
    with input_lock:
        pyautogui.moveRel(1, 0)
        pyautogui.moveRel(-1, 0)


def type_and_erase(phrase, cancelled=lambda: False):
    """Fake activity: type at a human pace, pause, then backspace it away.
    Stops typing as soon as cancelled() is true, but still erases what it typed."""
    with input_lock:
        typed = 0
        try:
            for c in phrase:
                if manual_cancel.is_set() or cancelled():
                    break
                if not 32 <= ord(c) <= 126:
                    continue
                pyautogui.write(c)
                typed += 1
                time.sleep(random.uniform(0.07, 0.22))
            if typed and not manual_cancel.is_set() and not cancelled():
                time.sleep(random.uniform(0.5, 1.5))
        finally:
            for _ in range(typed):
                pyautogui.press("backspace")
                time.sleep(random.uniform(0.05, 0.14))
        return typed


def jiggler():
    global jiggle_every
    while True:
        try:
            # random 70-130% spacing so it doesn't look robotic
            jiggle_wake.wait(jiggle_every * random.uniform(0.7, 1.3) if jiggle_every else None)
            jiggle_wake.clear()
            with input_lock:
                if jiggle_until and time.monotonic() > jiggle_until:
                    jiggle_every = 0
                if jiggle_every and not manual_cancel.is_set():
                    if jiggle_phrase:
                        phrase = jiggle_phrase
                        type_and_erase(phrase, lambda: jiggle_wake.is_set() or jiggle_phrase != phrase)
                    else:
                        nudge()
        except Exception as e:
            print(f"Jiggler error: {e}")


def reset_throttle():
    global global_locked_until
    with fail_lock:
        sources.clear()
        recent_fails.clear()
        global_locked_until = 0.0


def pin_ok(pin, source="", now=time.monotonic):
    """Check a PIN without ever sleeping. Each device is throttled (one try per 2 s) and locked
    out after MAX_FAILS wrong PINs, so a stranger cannot lock out the real phone; a global
    budget stops guessing spread across many addresses."""
    global global_locked_until
    with fail_lock:
        current = now()
        state = sources.setdefault(source, [0, 0.0, 0.0])
        if current < global_locked_until or current < state[2] or current < state[1]:
            return False
        if secrets.compare_digest(pin.encode(), PIN.encode()):
            sources.pop(source, None)
            return True
        state[0] += 1
        state[1] = current + 2
        if state[0] >= MAX_FAILS:
            state[0] = 0
            state[2] = current + LOCKOUT_S
            print(f"Too many wrong PINs from {source}: locked out for {LOCKOUT_S // 60} minutes.")
        recent_fails.append(current)
        while recent_fails[0] <= current - LOCKOUT_S:
            recent_fails.popleft()
        if len(recent_fails) >= GLOBAL_MAX_FAILS:
            recent_fails.clear()
            global_locked_until = current + LOCKOUT_S
            print(f"Too many wrong PINs overall: new logins wait {LOCKOUT_S // 60} minutes.")
        if len(sources) > 1000:  # forget devices with nothing pending
            for k in [k for k, v in sources.items() if v[0] == 0 and v[1] <= current and v[2] <= current]:
                del sources[k]
        return False


def hang_up(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class Client(socketserver.StreamRequestHandler):
    def setup(self):
        # One deadline for the whole login; per-read timeouts alone let a client drip forever.
        # Hang up on self.request as it is then: TLS wrapping takes over the raw socket.
        self.login_timer = threading.Timer(AUTH_DEADLINE_S, lambda: hang_up(self.request))
        self.login_timer.daemon = True
        self.login_timer.start()
        self.request.settimeout(5)
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        super().setup()

    def finish(self):
        self.login_timer.cancel()
        super().finish()

    def handle(self):
        self.request.settimeout(10)
        try:
            pin = str(json.loads(self.rfile.readline(256))["pin"])
        except (OSError, ValueError, KeyError, TypeError):
            return
        if not pin_ok(pin, self.client_address[0]):
            self.wfile.write(b'{"ok": false}\n')
            return
        self.login_timer.cancel()
        self.server.authenticated()
        self.request.settimeout(None)
        with input_lock:
            hello = {"ok": True, "os": sys.platform, "jiggle": jiggle_every, "phrase": jiggle_phrase,
                     "left": max(0, jiggle_until - time.monotonic()) if jiggle_until else 0}
        self.wfile.write(json.dumps(hello).encode() + b"\n")
        print(f"Connected: {self.client_address[0]}")
        pressed = set()
        try:
            while line := self.rfile.readline(MAX_LINE + 1):
                if len(line) > MAX_LINE:
                    print("Command too long; disconnecting.")
                    break
                try:
                    run(json.loads(line), pressed)
                except Exception as e:
                    print(f"Ignored bad command ({type(e).__name__})")  # never its content
        except OSError:
            pass
        finally:
            if pressed:
                with manual_input():
                    for b in pressed:
                        try:
                            pyautogui.mouseUp(button=b)
                        except Exception as e:
                            print(f"Could not release {b} button: {e}")
            print("Disconnected")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, tls):
        self.tls = tls
        self.connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.unauthed = threading.BoundedSemaphore(MAX_UNAUTHED)
        self.local = threading.local()  # per worker: has this client logged in?
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            self.close_request(request)
            return
        if not self.unauthed.acquire(blocking=False):  # strangers cannot fill every slot
            self.connections.release()
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.unauthed.release()
            self.connections.release()
            raise

    def authenticated(self):
        """Client.handle after a right PIN: its logging-in slot goes to the next device."""
        if not getattr(self.local, "authed", False):
            self.local.authed = True
            self.unauthed.release()

    def process_request_thread(self, request, client_address):
        self.local.authed = False
        try:
            super().process_request_thread(request, client_address)
        finally:
            if not self.local.authed:
                self.unauthed.release()
            self.connections.release()


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
    private_file(path)
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


def load_pin(path=PIN_FILE):
    if not path.exists():
        # owner-only (0600), so other accounts on this laptop cannot read the PIN
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(f"{secrets.randbelow(10**6):06d}")
    private_file(path)
    return path.read_text().strip()


def private_file(path):
    """Owner-only, also for files made by older versions. 0600 does nothing on Windows, so
    there drop inherited access and grant only the signed-in user."""
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        domain = os.environ.get("USERDOMAIN", "")
        who = f"{domain}\\{user}" if domain else user
        if user:
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:F"],
                           capture_output=True, check=False)
    else:
        os.chmod(path, 0o600)


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
