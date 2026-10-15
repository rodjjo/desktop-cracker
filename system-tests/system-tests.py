#!/usr/bin/env python3
"""The system test: **one boot, one pass** (`AGENTS.md`, "System testing").

    system-tests/system-tests.py [--only NAME[,NAME…]] [--skip NAME[,NAME…]] [--list]

`system-tests/run.sh` gives it a run directory; this file knows the steps, and a port it picks
itself (`free_port`) for each run it starts.

What it drives:

* the application, exactly as a user starts it (`--config … --plugin-path …`), through
  the **plugin** and nothing else: its switches, its own keys (`--window-command f9`) and its
  events.  No print, no file, no environment variable of ours;
* the root disk's passphrase: the person running the test types it, and the test hands it to the
  application as the answer to the application's own `question` event.  It is never written
  anywhere, and the environment never holds it (`AGENTS.md`, "Environment variables").

**One reader, always.**  The plugin's WebSocket is a stream, and two threads reading it would each
see half a message: one thread per run reads it — [`Run._read_loop`] — and every step waits by
*polling what that thread has collected* (`wait_until`, 200 ms).  The same thread answers the
application's questions, because an answer is what keeps the run moving and a step that is waiting
for the guest must not be the thing that blocks it.

The two steps this project uses, in order:

1. **boot-and-wrong-password** — a wrong passphrase must end the application, fast: the guest
   opens the disk as it starts (the passphrase travels the control channel), so it says so and
   the run ends within a few seconds rather than bringing up a guest that cannot work;
2. **the rest** — boot with the right passphrase and check everything in that one run: the
   desktop, the keys' actions, the display rule, the guest's own state, the run's honesty.
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import select
import stat
import threading
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# **The application this tree builds**: the project's binary (`desktop-cracker/app/desktop`), in
# this tree's own workspace. `make system-tests` passes the path it built, so a test run from
# a tree with a different layout still starts the right program.
APP = Path(os.environ.get("DESK_DESKTOP") or (ROOT / "target/release/desktop-cracker"))
PLUGIN = ROOT / "target/release/libdesk_plugin.so"
CONFIG = ROOT / "temp/config.yml"

# How long anything may take.  Generous on purpose: a microVM boots when it boots, and a test
# that is tight about it is a test that fails on a busy machine.  The **waits** in this file are
# on events, not on sleeps.
BOOT_TIMEOUT = float(os.environ.get("SYSTEM_TEST_BOOT_TIMEOUT", "180"))
STEP_TIMEOUT = float(os.environ.get("SYSTEM_TEST_STEP_TIMEOUT", "60"))

# The guest's readiness is the application's own milestone (`--ready-file` needs no switch here:
# the guest writes `control/guest-ready` itself, and the application prints when it is up).
READY = "guest ready in"

# The **unlock password** — the one the settings file holds a salted hash of, so a test can type it
# (`--set-password` is how a person sets it; this is the same secret, not a second one).  The root
# disk's passphrase is the one the person running the test is asked for, and it is never in an
# environment variable or a file: it is typed here and answered over the plugin.
UNLOCK_PASSWORD = os.environ.get("SYSTEM_TEST_UNLOCK_PASSWORD", "test")

# The password of the **LUKS disk the test makes for itself** (`additional-disks`): the guest's
# tool opens it with a password typed inside the guest, and this is that password.  It is the
# test's own disk and not the user's, so it is a constant here — the root disk's passphrase is
# the person's, and it is never written anywhere (`AGENTS.md`).
LUKS_TEST_PASSWORD = "changeme"

# The guest's display, as the settings file asks for it: a frame that is not this size is not the
# guest's screen.
DISPLAY_SIZE = (1280, 800)


# **One way to wait**: ask the same question every `POLL` seconds until it is true, and give up
# after the timeout.  Nothing sleeps longer than the answer takes, and a step that is waiting for
# something the application does at once never pays for a fixed pause.
POLL = 0.2


def wait_until(condition, timeout: float, what: str):
    """Run `condition` until it answers true, or fail saying what was waited for."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = condition()
        except Closed:
            raise
        except Exception as error:  # not ready yet is the normal case here
            last = error
        if last is True:
            return
        time.sleep(POLL)
    raise Failure(f"{what} (last answer: {last!r}, after {timeout}s)")


class Failure(Exception):
    """A step that did not hold.  The message is what the operator reads."""


class Closed(Exception):
    """The application is gone: its plugin closed the socket.  Some steps expect exactly that."""


class NotDrawn(Exception):
    """The window has nothing to hand out yet (`/frame` answered `409`).

    It is not a failure and it is not "the application is gone": the guest has not sent a frame
    yet, and a run whose window is still coming up is a run that is still coming up.
    """


def runtime_base() -> Path:
    """Where a run keeps its sockets.

    The **same rule the application has** (`dc_common::runtime_dir`): `$XDG_RUNTIME_DIR/desktop-cracker`, or `~/.desktop-cracker/run` where the session has no runtime
    directory.  A relative `$XDG_RUNTIME_DIR` is joined to the home, as the Rust does, and an empty
    one is the same as none.  It is deliberately *not* the test's `temp/` directory: the point of
    the rule is that a run's sockets are not where a working directory happens to be.
    """
    xdg = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if not xdg:
        # This project's own directory, which needs no name of its own inside it (and is kept short:
        # a unix socket's whole path has a limit the kernel enforces).
        return Path.home() / ".desktop-cracker" / "run"
    base = Path(xdg) if xdg.startswith("/") else Path.home() / xdg
    return base / "desktop-cracker"


class Run:
    """One application process, its plugin port, and what it has said.

    The socket has **one reader**: `_read_loop`, started by `connect`.  It appends every event to
    `events`, remembers the questions the application asked, and answers them — the root disk's
    passphrase and the unlock password with what the test knows, anything else with "no answer"
    (the application then does its own thing, exactly as it does with no plugin).
    """

    def __init__(self, run_dir: Path, plugin_port: int, config: Path):
        self.run_dir = run_dir
        self.plugin_port = plugin_port
        self.config = config
        self.process: subprocess.Popen | None = None
        self.events: list[dict] = []
        self.questions: list[dict] = []
        self.socket: socket.socket | None = None
        self.stdout: list[str] = []
        self._buf = b""
        # What the reader answers with.  A step sets these **before** `start`: the run that must
        # fail gets a wrong passphrase on purpose.
        self.disk_password: str | None = None
        self.unlock_password: str | None = UNLOCK_PASSWORD
        # The port the pass forwards to the guest's sshd (`--ssh-port`), chosen by `main` for each
        # run.  `None` means the pass does not ask for a forward at all.
        self.ssh_port: int | None = None
        # The **additional disks** the pass attaches (`--disk`), made by `main` when the
        # `additional-disks` step is in the pass: `[(name, path, mode)]`.
        self.disks: list[tuple[str, Path, str]] = []
        # The directory **each run of this pass** keeps its sockets in, recorded when it starts:
        # `<runtime base>/run-<pid>`, named after that run's own pid.  The pass checks at the end
        # that every one of them is gone.
        self.run_dirs: list[Path] = []
        self.closed = False
        self._stopping = threading.Event()
        self._reading = threading.Lock()
        self._reader: threading.Thread | None = None

    # ---------------------------------------------------------------- starting

    def start(self, extra: list[str] | None = None) -> None:
        """Start the application with the plugin, and wait for its plugin to answer."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        # A new run has heard nothing: the events of the one before it are not its own.
        self.events = []
        self.questions = []
        self.stdout = []
        self.closed = False
        self._buf = b""
        env = dict(os.environ)
        # **The one environment variable this project has**: the plugin's port.  It is the
        # plugin's, never the application's, and it carries a port and nothing else.
        env["DESK_PLUGIN_PORT"] = str(self.plugin_port)
        argv = [
            str(APP),
            "--config",
            str(self.config),
            "--plugin-path",
            str(PLUGIN),
        ] + (extra or [])
        self.process = subprocess.Popen(
            argv,
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # The run's own directory, named after its own pid. It
        # is **not** under `run_dir`: a run's sockets are not in a working directory, and that is
        # what keeps two runs — this one and another developer's — from meeting on one socket.
        self.run_dirs.append(runtime_base() / f"run-{self.process.pid}")

    def stop(self, timeout: float = 30.0) -> int:
        """Ask the application to finish **through its own interface**, and collect its status."""
        if self.process is None:
            return -1
        try:
            # The run is asked to end through the window's own `exit`; the reader answers any
            # question that comes out of shutting down.
            self.action("exit")
        except (Failure, Closed, urllib.error.URLError, OSError):
            # The application already ended (that is what this step proved): nothing to ask.
            pass
        try:
            rc = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                rc = self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                rc = self.process.wait(timeout=10)
        self._collect()
        self.close()
        return rc

    def close(self) -> None:
        """Stop the reader and give the socket back."""
        self._stopping.set()
        if self._reader is not None:
            self._reader.join(timeout=5)
            self._reader = None
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None

    def _collect(self) -> None:
        """Everything the application printed, read **without blocking**.

        A step's failure reads this as its explanation, so it is collected even while the
        application is still running: a pipe that is never drained fills up and stops the
        application, which would be the test breaking the thing it is testing.
        """
        stream = self.process.stdout if self.process is not None else None
        if stream is None:
            return
        fd = stream.fileno()
        while True:
            ready, _, _ = select.select([fd], [], [], 0)
            if not ready:
                break
            try:
                line = stream.readline()
            except (OSError, ValueError):
                break
            if not line:
                break
            self.stdout.append(line.rstrip("\n"))

    def exited(self) -> bool:
        return self.process is not None and self.process.poll() is not None

    # ---------------------------------------------------------------- the plugin

    def base(self) -> str:
        return f"http://127.0.0.1:{self.plugin_port}"

    def status(self) -> dict:
        self._collect()
        try:
            with urllib.request.urlopen(f"{self.base()}/status", timeout=10) as answer:
                return json.load(answer)
        except urllib.error.URLError as error:
            # The application is gone: that is an answer in itself, and one a step may want.
            raise Closed(str(error)) from error

    def get(self, path: str) -> str:
        """A text answer from the plugin (`/pin` is a table, and it is not JSON)."""
        self._collect()
        try:
            with urllib.request.urlopen(f"{self.base()}{path}", timeout=10) as answer:
                return answer.read().decode("utf-8", "replace")
        except urllib.error.URLError as error:
            raise Closed(str(error)) from error

    def frame(self) -> bytes:
        """The frame the window is about to draw, as a PNG (the plugin's own encoding)."""
        self._collect()
        request = urllib.request.Request(f"{self.base()}/frame", method="POST")
        try:
            with urllib.request.urlopen(request, timeout=20) as answer:
                return answer.read()
        except urllib.error.HTTPError as error:
            if error.code == 409:
                # "nothing has been drawn yet" — an answer, not a failure.
                raise NotDrawn() from error
            raise Closed(str(error)) from error
        except urllib.error.URLError as error:
            raise Closed(str(error)) from error

    def action(self, name: str) -> dict:
        """Run one of the window's **own** actions: `POST /action {"action": "…"}`.

        The application runs it — the plugin never acts on the run itself — and the answer says
        whether it did, and with which of the three codes this project uses.
        """
        body = json.dumps({"action": name}).encode()
        request = urllib.request.Request(
            f"{self.base()}/action",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as answer:
                reply = json.load(answer)
        except urllib.error.URLError as error:
            raise Closed(str(error)) from error
        if not reply.get("ran"):
            raise Failure(f"the action {name!r} did not run: {reply}")
        return reply

    # ---------------------------------------------------------------- the socket

    def connect(self) -> None:
        """Open the WebSocket, read the hello, and start the one reader.

        The application has to start and load the plugin first, which takes a moment: the port is
        tried until it answers, because "not yet" and "not at all" are different things and only
        the second one is a failure.
        """
        key = base64.b64encode(os.urandom(16)).decode()

        def listening() -> bool:
            try:
                self.socket = socket.create_connection(("127.0.0.1", self.plugin_port), timeout=10)
                return True
            except OSError:
                return False

        wait_until(
            listening,
            30,
            f"the plugin never listened on 127.0.0.1:{self.plugin_port} (is --plugin-path right?)",
        )
        handshake = (
            f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{self.plugin_port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(handshake.encode())
        head = self._read_until(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n")[0]:
            raise Failure(f"the plugin refused the WebSocket: {head!r}")
        # The accept key is the protocol's arithmetic; check it, because a client that does not
        # would happily talk to a server that got it wrong.
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if expected.encode() not in head:
            raise Failure("the plugin's WebSocket handshake is not the protocol's")
        hello = self.recv_event(timeout=10)
        if hello.get("event") != "hello":
            raise Failure(f"the first event was not the hello: {hello}")
        # **From here on there is one reader**, and it is not the step's thread.
        self.socket.setblocking(False)
        self._stopping.clear()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        """The single reader: collect every event, and answer the questions the run asks."""
        while not self._stopping.is_set():
            try:
                event = self.recv_event(timeout=0.2)
            except TimeoutError:
                continue
            except Closed:
                self.closed = True
                return
            except OSError:
                self.closed = True
                return
            if event.get("event") == "question":
                self._answer(event)

    def _answer(self, question: dict) -> None:
        """What the test answers: the two secrets it knows, and "no answer" for the rest.

        "No answer" is a legal answer: the application then does
        what it always does — its own dialog or its terminal prompt.
        """
        kind = question.get("kind")
        if kind == "disk-password":
            self.send_answer(question, self.disk_password)
        elif kind == "unlock-password":
            self.send_answer(question, self.unlock_password)
        else:
            self.send_answer(question, None)

    def _read_until(self, marker: bytes) -> bytes:
        data = b""
        deadline = time.time() + 10
        while marker not in data:
            if time.time() > deadline:
                raise Failure(f"the plugin did not answer in time: {data!r}")
            chunk = self.socket.recv(4096)  # type: ignore[union-attr]
            if not chunk:
                raise Failure("the plugin closed the connection")
            data += chunk
        head, _, rest = data.partition(marker)
        self._buf = rest
        return head + marker

    def recv_event(self, timeout: float = 10.0) -> dict:
        """One event from the socket, or a `TimeoutError`.  **The reader's thread only.**"""
        with self._reading:
            return self._recv_event(timeout)

    def _recv_event(self, timeout: float) -> dict:
        deadline = time.time() + timeout
        while True:
            frame = self._next_frame()
            if frame is not None:
                event = json.loads(frame)
                self.events.append(event)
                if event.get("event") == "question":
                    self.questions.append(event)
                return event
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError("no event arrived")
            ready, _, _ = select.select([self.socket], [], [], left)
            if ready:
                self._fill()

    def _fill(self) -> None:
        try:
            chunk = self.socket.recv(65536)  # type: ignore[union-attr]
        except BlockingIOError:
            return
        if not chunk:
            # The application is gone (its plugin went with it), which some steps expect.
            raise Closed()
        self._buf += chunk

    def _next_frame(self) -> str | None:
        """One complete text frame, or None when more bytes are needed."""
        if len(self._buf) < 2:
            return None
        b0, b1 = self._buf[0], self._buf[1]
        length = b1 & 0x7F
        offset = 2
        if length == 126:
            if len(self._buf) < 4:
                return None
            (length,) = struct.unpack("!H", self._buf[2:4])
            offset = 4
        elif length == 127:
            if len(self._buf) < 10:
                return None
            (length,) = struct.unpack("!Q", self._buf[2:10])
            offset = 10
        if len(self._buf) < offset + length:
            return None
        payload = self._buf[offset : offset + length]
        self._buf = self._buf[offset + length :]
        opcode = b0 & 0x0F
        if opcode == 0x8:  # close
            raise Closed()
        if opcode == 0x1:
            return payload.decode()
        return None

    def send_answer(self, question: dict, answer: str | bool | None) -> None:
        """Answer a question, masked, the way a client must."""
        if answer is None:
            payload = json.dumps({"answer": None, "id": question["id"]}).encode()
        elif isinstance(answer, bool):
            payload = json.dumps(
                {"answer": {"confirm": answer}, "id": question["id"]}
            ).encode()
        else:
            payload = json.dumps(
                {"answer": {"password": answer}, "id": question["id"]}
            ).encode()
        self.socket.sendall(self._masked(payload))  # type: ignore[union-attr]
        # The password is gone from this process the moment it is sent: the buffer is dropped
        # and the string is not kept anywhere.
        del payload

    @staticmethod
    def _masked(payload: bytes) -> bytes:
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
        length = len(payload)
        if length < 126:
            header = bytes([0x81, 0x80 | length])
        elif length < (1 << 16):
            header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", length)
        else:
            header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", length)
        return header + mask + masked

    # ---------------------------------------------------------------- waiting

    def wait_for_event(self, name: str, timeout: float = STEP_TIMEOUT) -> dict:
        """An event by name, from what the reader has collected (or is about to)."""
        found: list[dict] = []

        def arrived() -> bool:
            for event in self.events:
                if event.get("event") == name:
                    found.append(event)
                    return True
            return False

        wait_until(arrived, timeout, f"no {name!r} event arrived")
        return found[0]

    def heard(self, needle: str) -> dict | None:
        """Did the application already say this?  (A milestone, as the `log` event it became.)"""
        for event in self.events:
            if event.get("event") == "log" and needle in event.get("message", ""):
                return event
        return None

    def wait_for_log(self, needle: str, timeout: float = STEP_TIMEOUT) -> dict:
        """A milestone the application wrote, as the `log` event it became."""
        wait_until(
            lambda: self.heard(needle) is not None,
            timeout,
            f"the application never said {needle!r}",
        )
        return self.heard(needle) or {}

    # ---------------------------------------------------------------- ssh

    def ssh(
        self,
        command: str,
        port: int,
        user: str = "deskuser",
        password: str = "changeme",
        timeout: float = 60.0,
    ) -> tuple[int, str]:
        """Run `command` in the guest over ssh, through the **forwarded port**.

        `ssh_client.py` (beside this file) is the client: it talks the ssh protocol with paramiko,
        so the test can assert on what a person's `ssh` would give them.  The password goes to it
        **on standard input** — never in an argument, never in the environment, never in a file
        (`AGENTS.md`, "Environment variables").

        `timeout` is the client's whole budget, and it is spent **retrying a connection the guest
        resets**: the forward answers from the moment the microVM starts, while the guest's own
        `ssh.service` comes up with its systemd a few seconds later (measured: the door is open at
        the run's fifth second and a login succeeds around the twenty-fifth).  A person typing
        `ssh` would do the same.

        The answer is `(exit status, everything it printed)`: the remote command's own status, or
        `255` when there was no login at all (a refused connection, a refused password).
        """
        client = subprocess.run(
            [
                sys.executable,
                str(ROOT / "system-tests/ssh_client.py"),
                "--port",
                str(port),
                "--user",
                user,
                "--timeout",
                str(timeout),
                "--",
                command,
            ],
            cwd=ROOT,
            input=password + "\n",
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        return client.returncode, (client.stdout or "") + (client.stderr or "")


# -------------------------------------------------------------------- the steps


def step_boot_and_wrong_password(run: Run, password: str) -> None:
    """A **wrong** passphrase must end the application, fast.

    The guest opens the disk as it starts, so the refusal is its own words within a few seconds:
    no usable guest, and the run ends non-zero.
    """
    # The answer is a wrong one **on purpose**: the application must refuse to start at all.
    run.disk_password = password + "-certainly-wrong"
    run.start()
    run.connect()
    wait_until(
        run.exited,
        30,
        "a wrong passphrase did not end the application",
    )
    rc = run.stop(timeout=10)
    if rc == 0:
        raise Failure("the application exited 0 on a wrong passphrase (it must fail)")
    # **Why** it ended matters: a run that failed for some other reason (a locked image, a missing
    # kernel) is not this step passing.
    said = "\n".join(run.stdout[-12:])
    logs = "\n".join(
        e.get("message", "") for e in run.events if e.get("event") == "log"
    )
    both = f"{said}\n{logs}".lower()
    # **The guest's own words** on this path: the initramfs is what opens the container, so the
    # refusal reads `the password did not open the container` (a machine that reported a raw
    # `keyslot` or that it could not open the disk).  Either sentence is the step passing.
    said_the_disk = any(
        phrase in both
        for phrase in ("open the disk", "keyslot", "did not open the container", "could not be unlocked")
    )
    if "password" not in both or not said_the_disk:
        raise Failure(
            "the run ended, but not because of the passphrase:\n"
            f"  status: {rc}\n  output: {said.strip()}\n  events: {logs}"
        )


def step_boot(run: Run, password: str) -> None:
    """The one boot the whole pass shares: start, answer the question, wait for the guest.

    The answer to the root disk's question is **the reader's**, so this step only waits: for the
    application's own milestone that the guest is up, and for the window to be drawing.
    """
    run.disk_password = password
    run.start(
        [
            "--ready-file",
            str(run.run_dir / "control/guest-ready"),
            # **One vCPU, for the duration of the test** (the operator, 2026-10-08: "during the
            # tests, and only during the tests make the microvm's CPU be only one CPU").  A
            # guest given every core of this host spends its time in per-CPU bring-up and its
            # own watchdog reports soft lockups; the test is not measuring boot speed, and the
            # switch that asks for this is the application's own (`--vcpus`), not a test hook.
            "--vcpus",
            "1",
        ]
        + (["--ssh-port", str(run.ssh_port)] if run.ssh_port is not None else [])
        + [
            argument
            for (_name, path, mode) in run.disks
            for argument in ("--disk", f"{path}:{mode}")
        ]
    )
    run.connect()
    ready = run.wait_for_log(READY, timeout=BOOT_TIMEOUT)
    print(f"      {ready.get('message')}")
    # **The microVM is pinned to the host's physical cores, and the test says so**: the plugin reports the fact in
    # `/status`, so it is asserted here rather than trusted — the run's vCPU threads each hold a
    # core of their own, and the CPUs are a list of this host's physical cores (never two
    # hyper-threads of one core).  A machine with one vCPU (the `--vcpus 1` above) pins exactly
    # one thread; what matters is that the pinning happened and that the list is the host's own.
    def pinned_ok() -> bool:
        pin = run.status().get("pinning") or {}
        return (
            pin.get("format") in (1, 2)
            and pin.get("cpus_list")
            and pin.get("vcpus") == 1
            and pin.get("vcpus_pinned", 0) >= 1
            and pin.get("host_cores", 0) >= 1
        )

    wait_until(pinned_ok, BOOT_TIMEOUT, "the microVM's vCPUs were not pinned to host cores")
    pin = run.status()["pinning"]
    print(f"      pinned: vCPU 1 on host core {pin['cpus_list']} ({pin['host_cores']} physical core(s))")
    # The same fact in the shape a shell wants, which is what a study reads.
    csv = run.get("/pin")
    assert csv.splitlines()[:2] == ["cpu,vcpu", csv.splitlines()[1]], csv
    # And the window draws: the display is part of the run's own mode, so a run whose window never
    # shows a frame is not a run this test accepts.  The frames are counted by the run itself.
    wait_until(
        lambda: run.status()["frames"] > 0,
        BOOT_TIMEOUT,
        "the window never drew a frame",
    )
    # **The window goes off the screen here**, and stays off for the rest of the pass: a test that
    # puts a window in front of the person at the machine is a test disturbing them, and the plugin
    # exists so it does not have to (`AGENTS.md`; the plugin's own contract, "What a test does
    # with it"). The run still *has* its window — the run's own mode always does, and the display
    # rule is checked below — and the window's own action is how it is taken away.
    # **The window goes off the screen here** — and it is already off when the run has a plugin
    # (Plugins: "If the plugin is loaded, desktop-cracker will hide the main window
    # by default during the run").  Asking `hide-or-show` on a window that is already hidden is a
    # different thing from putting it away: it asks the **unlock password** and shows the window
    # again, which is what a person would see and not what this step means.  So the action is asked
    # for exactly when there is something on screen to put away.
    if run.status()["visible"]:
        run.action("hide-or-show")
        wait_until(
            lambda: not run.status()["visible"],
            STEP_TIMEOUT,
            "the window did not go off the screen when the action asked it to",
        )
    print("      the window is off the screen for the rest of the pass")

def step_desktop_is_drawn(run: Run, _password: str) -> None:
    """The frame the window is about to draw is the **guest's desktop**.

    `POST /frame` is the picture itself, so this is a measurement rather than a hope: a desktop
    is many colours and a mid-range mean; a black screen is one colour and a mean of zero.
    """
    # The window draws the guest's screen a frame at a time, and the guest's desktop arrives when
    # the guest's own session has started: what is asked for is a frame that **is** a desktop, and
    # the question is put again until it is (a black frame is the guest still coming up).
    # What the frame looked like the last time it was asked for, so a guest that is still coming
    # up says so once per shape rather than once per poll.
    last = None

    def a_desktop() -> bool:
        nonlocal last
        try:
            png = run.frame()
        except NotDrawn:
            # The guest has not sent a frame yet: that is a stage, not a failure.
            if last != "nothing":
                print("      nothing has been drawn yet (the guest is still coming up)")
                last = "nothing"
            return False
        if not png.startswith(b"\x89PNG"):
            raise Failure("POST /frame did not answer a PNG")
        width, height, colours, mean = describe_png(png)
        if (width, height) != DISPLAY_SIZE:
            raise Failure(
                f"the frame is {width}x{height}, not the guest's "
                f"{DISPLAY_SIZE[0]}x{DISPLAY_SIZE[1]}"
            )
        if colours < 1000:
            if last != colours:
                print(f"      frame {width}x{height}, {colours} colours: the guest is still coming up")
                last = colours
            return False
        print(f"      frame {width}x{height}, {colours} colours, mean {mean:.1f}")
        return True

    wait_until(a_desktop, BOOT_TIMEOUT, "the window never drew the guest's desktop")


def step_window_rule(run: Run, _password: str) -> None:
    """The display rule: the window is the guest's size, whatever the numlock key does.

    The window is the guest's size — the geometry the guest's own scanout arrives at.  The numlock
    key is what the two chords are made of; it never resizes the window, never paints it black, and
    it is not the sound rule either (the sound follows the window's visibility alone).  It is
    asserted on `/status`, which is the application's own state.
    """
    status = run.status()
    if (status.get("width"), status.get("height")) != DISPLAY_SIZE:
        raise Failure(
            f"the guest's screen is {status.get('width')}x{status.get('height')}, not the "
            f"{DISPLAY_SIZE[0]}x{DISPLAY_SIZE[1]} the settings ask for (the numlock key is "
            f"not what sizes the window)"
        )


def step_guest_state(run: Run, _password: str) -> None:
    """The guest's own state: the run is `running`, and the events said so."""
    states = [e.get("state") for e in run.events if e.get("event") == "state"]
    if "running" not in states:
        raise Failure(f"the run never reached `running`: {states}")
    status = run.status()
    if status.get("state") != "running":
        raise Failure(f"/status says {status.get('state')!r}, not `running`")


def step_the_runs_own_sockets(run: Run, _password: str) -> None:
    """The run's sockets are **its own**, in this user's runtime directory.

    The rule has three parts and all three are checked here, on the machine this pass already
    booted — no second boot, no second application:

    * the Firecracker **API socket** — the channel between the microVM and this application — is at
      `<runtime base>/run-<pid>/api.sock`, where `<runtime base>` is
      `$XDG_RUNTIME_DIR/desktop-cracker` (or `~/.desktop-cracker/run`);
    * the machine's other channels — the vsock listener the guest's devices are served on, and the
      control directory beside them — are in **the same directory**, so one run's plumbing is one
      place to look at and one place to remove;
    * that directory is **not** a path the whole machine shares: nothing of a run sits under `/tmp`,
      which is what let one developer's run interfere with another's.

    The pid is taken from `/status`, which `step_status_is_honest` already checked is the run's own
    process id — so this is the *application's* pid, not the test's guess.
    """
    pid = run.status()["pid"]
    own = runtime_base() / f"run-{pid}"
    if not own.is_dir():
        raise Failure(
            f"the run has no directory of its own at {own} "
            f"(the runtime directory is {runtime_base()})"
        )
    api = own / "api.sock"
    if not api.exists():
        raise Failure(f"the run's API socket is not at {api}: {sorted(p.name for p in own.iterdir())}")
    mode = api.stat().st_mode
    if not stat.S_ISSOCK(mode):
        raise Failure(f"{api} is not a socket file (mode {stat.S_IMODE(mode):o})")
    if not (own / "v.sock").exists():
        raise Failure(
            "the guest's channels are not beside the API socket: "
            f"{sorted(p.name for p in own.iterdir())}"
        )
    # The directory is private: a socket a run listens on is a door into that run.
    if stat.S_IMODE(own.stat().st_mode) & 0o077:
        raise Failure(
            f"{own} is reachable by somebody else "
            f"(mode {stat.S_IMODE(own.stat().st_mode):o}, and a run's sockets are its user's own)"
        )
    for path in (own, api):
        if str(path).startswith("/tmp/"):
            raise Failure(f"a run's socket is in a path the whole machine shares: {path}")
    names = sorted(p.name for p in own.iterdir())
    print(f"      {own}: {', '.join(names)}")


def step_status_is_honest(run: Run, _password: str) -> None:
    """`/status` reports the run it is attached to: the protocol, the pid, the frame count."""
    status = run.status()
    for field in ("protocol", "pid", "state", "frames", "dropped"):
        if field not in status:
            raise Failure(f"/status has no {field!r}: {json.dumps(status)}")
    if status["pid"] != run.process.pid:  # type: ignore[union-attr]
        raise Failure(f"/status reports pid {status['pid']}, the run is {run.process.pid}")
    if status["protocol"] != 1:
        raise Failure(f"the plugin speaks protocol {status['protocol']}, the test speaks 1")
    if status["frames"] < 1:
        raise Failure("the window has not drawn a frame")


def step_one_client_only(run: Run, _password: str) -> None:
    """The plugin serves **exactly one** client: a second `/ws` is refused with `409`.

    It is what makes "who answers the question" unambiguous: the
    plugin is the test's handhold on the run, and a second client would be a second answer to the
    same question.  The refusal is the protocol's own answer, so it is asserted where a client can
    see it — and the first client is checked to be still served afterwards.
    """
    key = base64.b64encode(os.urandom(16)).decode()
    with socket.create_connection(("127.0.0.1", run.plugin_port), timeout=10) as second:
        second.sendall(
            (
                f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{run.plugin_port}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        head = second.recv(4096).decode(errors="replace")
    status = head.split("\r\n")[0]
    if "409" not in status:
        raise Failure(f"a second client was not refused: {status!r}")
    print(f"      a second client got {status!r}")
    if run.status().get("protocol") != 1:
        raise Failure("the plugin stopped serving its first client")


def step_window_actions(run: Run, _password: str) -> None:
    """The window's **own** actions run when a client asks for them.

    They are the keys' actions — the same code the keyboard drives — so a test can bring the window
    back and put it away without a person at the keyboard.  `hide-or-show` on a hidden window asks
    the **unlock password** (over the plugin, like every other question), and on a window that is on
    screen it simply hides it.  The step starts from the run's resting state — the window off the
    screen, where the boot left it — so the question is exercised and the pass ends as it began.
    """
    if run.status()["visible"]:
        raise Failure("the window is on screen before the step that hides it")
    # Show: the application asks the unlock password, and the reader answers it.
    run.action("hide-or-show")
    wait_until(
        lambda: run.status()["visible"],
        STEP_TIMEOUT,
        "the window did not come back when the action asked it to",
    )
    # Hide: nothing is asked, the window simply goes away again.
    run.action("hide-or-show")
    wait_until(
        lambda: not run.status()["visible"],
        STEP_TIMEOUT,
        "the window did not hide when the action asked it to",
    )


def step_no_plugin_is_the_normal_run(run: Run, _password: str) -> None:
    """With no `--plugin-path` the application is the run a person gets.

    It is asserted on the application's **own** interface, because there is no plugin to ask: the
    switch is optional, and `--show-settings` is how a run says what it would do without doing it.
    """
    argv = subprocess.run(
        [str(APP), "--show-settings", "--config", str(run.config)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if argv.returncode != 0:
        raise Failure(f"--show-settings failed: {argv.stderr.strip()}")
    if "root_disk" not in argv.stdout:
        raise Failure("--show-settings did not print the settings")


def step_ssh(run: Run, _password: str) -> None:
    """The guest's **sshd**, through the forwarded port.

    The pass boots the run with `--ssh-port <a port this test picked>`, so the host's loopback port
    is carried into the guest's port 22 — and this step logs in over it, as the guest's own user and
    with the guest's own password.  It is the whole point of the feature: the port forward, the
    relay's inbound flow, and an sshd that is really running inside the guest, asserted end to end.

    It also asserts the two halves of the rule that matter: **root is not a login** (the
    distribution's `prohibit-password`), and the run's own words name the address it opens — with
    the switch, and never without it (`step_ssh_is_not_forwarded_by_default`).
    """
    if run.ssh_port is None:
        # `--only ssh` picks a port; a pass that skips the switch has nothing to log in to.
        print("      skipped: this pass was not given an --ssh-port")
        return
    # The application must have said what it opened, and it is the port this test asked for.
    said = run.wait_for_log("is forwarded to the guest's sshd", timeout=STEP_TIMEOUT)
    if f"127.0.0.1:{run.ssh_port}" not in said.get("message", ""):
        raise Failure(f"the run forwarded something else: {said.get('message')!r}")

    status, output = run.ssh("id -un && grep -c '^deskuser:' /etc/passwd", run.ssh_port)
    if status != 0:
        raise Failure(f"ssh into the guest failed ({status}):\n{output}")
    if "deskuser" not in output:
        raise Failure(f"the guest answered something else:\n{output}")
    print(f"      ssh -p {run.ssh_port} deskuser@127.0.0.1 -> {output.strip().splitlines()[-1]}")

    # **root is not a login over ssh**: the password is the right one, and the answer is still no.
    # 255 is the client's own "no login", which is exactly what a refused password is.
    status, output = run.ssh("id -un", run.ssh_port, user="root", password="deskuser")
    if status == 0:
        raise Failure(f"root logged in over ssh, which this project forbids:\n{output}")
    if status != 255:
        raise Failure(
            f"root's ssh attempt ended with {status}, not a refused login:\n{output}"
        )
    print("      root over ssh is refused (the guest's own prohibit-password)")


def step_ssh_is_not_exposed_beyond_the_loopback(run: Run, _password: str) -> None:
    """The forward is the host's **loopback**, and nothing else opens a port.

    Two halves of the same rule, both of them about a port that is *not* opened:

    * the port the run was given is reachable on `127.0.0.1` and **not** on any of this host's own
      addresses — a guest reached only from the machine the user is sitting at;
    * a port no run was told about is closed: nothing in this application listens unless the user
      asked for it, which is what "without `--ssh-port` we do not expose the ssh service" is.
    """
    if run.ssh_port is None:
        print("      skipped: this pass was not given an --ssh-port")
        return

    def connects(host: str, port: int, timeout: float = 3.0) -> bool:
        with socket.socket() as probe:
            probe.settimeout(timeout)
            return probe.connect_ex((host, port)) == 0

    if not connects("127.0.0.1", run.ssh_port):
        raise Failure(f"the run does not hold 127.0.0.1:{run.ssh_port}, the port it was given")

    # This host's own addresses, the ones a LAN neighbour would dial: the forward must not answer
    # there.  A host with only a loopback address has nothing to check, and says so.
    elsewhere = []
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        address = info[4][0]
        if address.startswith("127.") or address in elsewhere:
            continue
        elsewhere.append(address)
    for address in elsewhere:
        if connects(address, run.ssh_port, timeout=2.0):
            raise Failure(
                f"the forward answers on {address}:{run.ssh_port}, not only on the loopback"
            )
    # A port nobody asked for: closed, so a run with no `--ssh-port` exposes nothing.
    free = free_port()
    if connects("127.0.0.1", free, timeout=2.0):
        raise Failure(f"something is listening on 127.0.0.1:{free}, which no run was told about")
    print(
        f"      127.0.0.1:{run.ssh_port} is open, {free} is closed"
        + (f", and {', '.join(elsewhere)} do not answer" if elsewhere else "")
    )


def step_additional_disks(run: Run, _password: str) -> None:
    """The **additional disks**: attached by the run, listed and mounted inside the guest.

    Settings: asks for a list of disks the *user* mounts himself, and the operator's
    rule for this step is that the disks are small: the pass makes two 16 MiB images of its own
    (`make_test_disks`) \u2014 one plain ext4 and one LUKS container \u2014 and asserts the whole path:

    * the run **attached** them (its own words, and the plan the guest reads in the control
      share names the device each one became);
    * the guest sees them as block devices of their own (`/dev/vdb`, `/dev/vdc`), and
      **nothing mounted them** \u2014 the application's job ends at the attachment;
    * the guest's own tool, `desk-disk-mount`, lists them (with what is on each one) and
      mounts them: a plain filesystem directly, and the LUKS container with a password typed
      **inside the guest**;
    * and the **disk application the user actually clicks** — `Disks` (gnome-disk-utility) over
      `udisks2` over polkit — has its path open in this guest: the service is running, the crypto
      plugin it calls is in the userland, and polkit answers yes for the user of the guest's own
      console.
    """
    if not run.disks:
        print("      skipped: this pass made no test disks")
        return
    # The run's own account of what it attached, one line per disk.
    for name, path, _mode in run.disks:
        said = run.wait_for_log(f"disk {name}:", timeout=STEP_TIMEOUT)
        if str(path) not in said.get("message", ""):
            raise Failure(f"the run attached something else for {name}: {said.get('message')!r}")
    print("      the run attached: " + ", ".join(name for name, _, _ in run.disks))

    # What the guest is told: device, name, mode.  It is written before the guest boots and it is
    # the only way the guest can say which /dev/vdX is which.
    status, plan = run.ssh("cat /run/desktop-cracker/disks", run.ssh_port)
    if status != 0:
        raise Failure(f"the guest could not read the disks plan:\n{plan}")
    for expect in ("/dev/vdb plain rw", "/dev/vdc locked rw"):
        if expect not in plan:
            raise Failure(f"the disks plan does not say {expect!r}:\n{plan}")
    print("      the guest's plan: " + " | ".join(plan.strip().splitlines()[1:]))

    # The devices are there, and **nothing mounted them**: the attachment is the whole of what
    # the run does with an additional disk.
    status, seen = run.ssh(
        "ls -l /dev/vdb /dev/vdc; echo ---; findmnt -no SOURCE | grep -c '^/dev/vd[bc]' || true",
        run.ssh_port,
    )
    if status != 0 or "/dev/vdb" not in seen or "/dev/vdc" not in seen:
        raise Failure(f"the guest does not see the attached disks:\n{seen}")
    if "\n1" in seen:
        raise Failure(f"one of the attached disks was mounted for the user:\n{seen}")
    print("      /dev/vdb and /dev/vdc are attached and unmounted")

    # The guest's tool: it lists them, with what is inside each one.
    status, listing = run.ssh("desk-disk-mount list", run.ssh_port)
    if status != 0:
        raise Failure(f"desk-disk-mount list failed:\n{listing}")
    for expect in ("plain", "locked", "LUKS"):
        if expect not in listing:
            raise Failure(f"the tool's listing does not mention {expect!r}:\n{listing}")
    print("      desk-disk-mount list: " + " | ".join(listing.strip().splitlines()[1:3]))

    # A **plain** filesystem: mounted directly, and the guest can write in it.
    status, mounted = run.ssh(
        "printf '%s\\n' " + shell_quote(LUKS_TEST_PASSWORD)
        + " | desk-disk-mount open plain /mnt/plain && "
        "echo written-by-the-system-test > /mnt/plain/hello && cat /mnt/plain/hello && "
        "mountpoint -q /mnt/plain && echo mounted",
        run.ssh_port,
    )
    if status != 0 or "written-by-the-system-test" not in mounted or "mounted" not in mounted:
        raise Failure(f"the plain disk could not be mounted and used:\n{mounted}")
    print("      the plain disk is mounted at /mnt/plain and written in")

    # A **LUKS container**: the same tool, and the password is typed in the guest.  The first
    # line of standard input is `sudo`'s (the tool re-runs itself as root), and the second is
    # `cryptsetup`'s.  **Which of the two is the passphrase is the tool's own choice**, and this
    # is the one place a person's two answers differ: for a container the second line is the
    # passphrase, and for a plain filesystem there is no second answer — so the test gives it the
    # same one twice, which is what a person reading the two prompts would type.
    #
    # A password is never an argument, on either side of the machine.
    password = shell_quote(LUKS_TEST_PASSWORD)
    status, opened = run.ssh(
        f"printf '%s\\n%s\\n' {password} {password} | "
        "desk-disk-mount open locked /mnt/locked && "
        "echo written-through-luks > /mnt/locked/hello && cat /mnt/locked/hello && "
        "mountpoint -q /mnt/locked && echo mounted",
        run.ssh_port,
    )
    if status != 0 or "written-through-luks" not in opened or "mounted" not in opened:
        raise Failure(f"the LUKS disk could not be opened and mounted:\n{opened}")
    print("      the LUKS disk is open and mounted at /mnt/locked")

    # And closing it puts everything back: the mount goes, the container goes with it.  Unmounting
    # is root's too, so the tool re-runs itself under `sudo` here as it did for the open — and the
    # line it reads for that is the same one.
    status, closed = run.ssh(
        "printf '%s\n' " + shell_quote(LUKS_TEST_PASSWORD)
        + " | desk-disk-mount close locked /mnt/locked; "
        "mountpoint -q /mnt/locked || echo closed",
        run.ssh_port,
    )
    if status != 0 or "closed" not in closed:
        raise Failure(f"the LUKS disk could not be closed again:\n{closed}")
    print("      and closed again (the mount and the container are gone)")

    # **And the same disks through the guest's own disk application**: `Disks` does not call `cryptsetup` itself, it asks `udisks2`, and
    # `udisks2` asks **polkit**.  A click on Disks is a dialog and a dialog is the operator's test
    # (`AGENTS.md`), so what is asserted here is the three facts a click depends on, in the same
    # boot: the service is up, the crypto plugin it calls is really in the userland (its absence is
    # the 2026-10-14 bug — `The function 'bd_crypto_luks_open_blob' called, but not implemented!`),
    # and the four actions a **virtio** disk makes it ask for are answered for the user sitting on
    # this guest's own console (`/etc/polkit-1/rules.d/50-desk-disks.rules`).
    status, manager = run.ssh(
        "systemctl is-active udisks2; "
        "find /usr/lib -name 'libbd_crypto.so.*' -print -quit; "
        "P=$(pgrep -u $(id -u) -f xfce4-session | head -1); echo session_pid=$P; "
        "for a in filesystem-mount-system filesystem-unmount-others "
        "encrypted-unlock-system encrypted-lock-others; do "
        "pkcheck -a org.freedesktop.udisks2.$a -p $P >/dev/null 2>&1; echo \"$a=$?\"; done",
        run.ssh_port,
    )
    if status != 0:
        raise Failure(f"the guest's disk manager could not be asked about:\n{manager}")
    if "active" not in manager.splitlines()[0]:
        raise Failure(f"udisks2 — the service Disks talks to — is not running:\n{manager}")
    if "libbd_crypto" not in manager.splitlines()[1]:
        raise Failure(f"libblockdev's crypto plugin is not in the userland:\n{manager}")
    denied = [line for line in manager.splitlines() if line.endswith("=2")]
    if denied:
        raise Failure(
            "polkit refuses these actions for the guest's own desktop session "
            f"(Disks would ask for a password nobody has):\n{manager}"
        )
    print("      Disks' own path is open: udisks2 active, the crypto plugin present, "
          "polkit answers yes for the desktop session")


def shell_quote(text: str) -> str:
    """`text` as one shell word: this is a test writing a command, and a password with a quote in
    it must not become a second command."""
    return "'" + text.replace("'", "'\\''") + "'"


def make_test_disks(directory: Path) -> list[tuple[str, Path, str]]:
    """Two **tiny disks** for the pass: one plain filesystem, one LUKS container.

    The operator's rule for the system test is that a disk the test needs is small — "use very
    small empty disks, just enough to check the feature" — so both are 16 MiB images made here,
    in the pass's own directory, with no userland in them: what is being tested is that a disk
    the run was given becomes a block device inside the guest and that the guest's own tool can
    mount it, and neither of those depends on the disk being big.
    """
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    plain = directory / "plain.img"
    locked = directory / "locked.img"
    key = directory / "key"
    # **The key file is the passphrase, byte for byte.**  `cryptsetup --key-file` takes the file's
    # whole content as the key, so a trailing newline in this file would make the container's
    # passphrase `changeme\n` — and the guest's tool, which takes the passphrase the way a person
    # types it (a line of input, its newline not part of the secret), would then be handing
    # cryptsetup the right password and be told `No key available with this passphrase` (measured
    # 2026-10-10).  The fixture is what makes the container, so the fixture is where the two have
    # to agree.
    key.write_text(LUKS_TEST_PASSWORD)
    # `mke2fs`/`cryptsetup` are the host's own tools here (the pass runs on the host, and these
    # two images are the *inputs*): a plain ext4 and a LUKS1 container with an ext4 inside it,
    # which is what `desk-disk create` makes for the guest.
    script = (
        "set -e; "
        "truncate -s 16M /w/plain.img; mke2fs -q -F -t ext4 -L plain /w/plain.img; "
        "truncate -s 16M /w/locked.img; "
        "cryptsetup luksFormat --type luks1 --batch-mode --key-file /w/key /w/locked.img; "
        "cryptsetup luksOpen --key-file /w/key /w/locked.img desktop-cracker-test; "
        "mke2fs -q -F -t ext4 -L locked /dev/mapper/desktop-cracker-test; "
        "cryptsetup luksClose desktop-cracker-test; "
        # The container writes them as **root**; the run is this user, and an image the run
        # cannot open is not attached at all (measured: a run refused with "Could not open ...:
        # Permission denied" rather than starting a guest with a device it cannot read).
        f"chown {os.getuid()}:{os.getgid()} /w/plain.img /w/locked.img"
    )
    made = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "-v",
            f"{directory}:/w",
            "debian:12",
            "bash",
            "-c",
            f"apt-get update -qq >/dev/null 2>&1; "
            f"apt-get install -y -qq e2fsprogs cryptsetup util-linux >/dev/null 2>&1; {script}",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if made.returncode != 0:
        raise Failure(
            "the test's own disks could not be made (docker, e2fsprogs and cryptsetup are "
            f"needed): {made.stderr.strip()[-400:]}"
        )
    key.unlink()
    # The two disks are attached read-write: what the step asserts is that the guest can mount
    # them and that the host's own account of each one is honest.
    return [("plain", plain.resolve(), "rw"), ("locked", locked.resolve(), "rw")]



STEPS = [
    ("boot-and-wrong-password", step_boot_and_wrong_password),
    ("boot", step_boot),
    ("desktop-is-drawn", step_desktop_is_drawn),
    ("window-rule", step_window_rule),
    ("guest-state", step_guest_state),
    ("the-runs-own-sockets", step_the_runs_own_sockets),
    ("status-is-honest", step_status_is_honest),
    ("one-client-only", step_one_client_only),
    ("ssh", step_ssh),
    ("additional-disks", step_additional_disks),
    ("ssh-port-is-the-loopbacks-only", step_ssh_is_not_exposed_beyond_the_loopback),
    ("window-actions", step_window_actions),
    ("no-plugin-is-the-normal-run", step_no_plugin_is_the_normal_run),
]


def describe_png(png: bytes) -> tuple[int, int, int, float]:
    """The size, the number of distinct colours and the mean brightness of a PNG.

    It is done with the standard library only (`zlib` + the PNG's own filters), because the test
    runs on a machine that may have nothing else installed.
    """
    width, height, rows = decode_png(png)
    colours = set()
    total = 0
    count = 0
    for line in rows:
        for i in range(0, len(line), 3):
            pixel = bytes(line[i : i + 3])
            colours.add(pixel)
            total += pixel[0] + pixel[1] + pixel[2]
            count += 3
    return width, height, len(colours), total / max(1, count)


def decode_png(png: bytes) -> tuple[int, int, list[bytearray]]:
    """A PNG as rows of RGB bytes, filters undone.  `zlib` and the protocol's own arithmetic."""
    import zlib

    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise Failure("not a PNG")
    pos = 8
    width = height = 0
    idat = b""
    while pos < len(png):
        (length,) = struct.unpack("!I", png[pos : pos + 4])
        kind = png[pos + 4 : pos + 8]
        body = png[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour = struct.unpack("!IIBB", body[:10])
            if (depth, colour) != (8, 2):
                raise Failure(f"unexpected PNG format: depth {depth}, colour {colour}")
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride = width * 3
    rows: list[bytearray] = []
    previous = bytearray(stride)
    offset = 0
    for _ in range(height):
        filter_type = raw[offset]
        offset += 1
        line = bytearray(raw[offset : offset + stride])
        offset += stride
        unfilter(filter_type, line, previous, 3)
        rows.append(line)
        previous = line
    return width, height, rows


def unfilter(kind: int, line: bytearray, previous: bytearray, bpp: int) -> None:
    """The PNG filters, in place."""
    if kind == 0:
        return
    for i in range(len(line)):
        left = line[i - bpp] if i >= bpp else 0
        up = previous[i]
        up_left = previous[i - bpp] if i >= bpp else 0
        if kind == 1:
            line[i] = (line[i] + left) & 0xFF
        elif kind == 2:
            line[i] = (line[i] + up) & 0xFF
        elif kind == 3:
            line[i] = (line[i] + ((left + up) >> 1)) & 0xFF
        elif kind == 4:
            p = left + up - up_left
            pa, pb, pc = abs(p - left), abs(p - up), abs(p - up_left)
            predictor = left if (pa <= pb and pa <= pc) else (up if pb <= pc else up_left)
            line[i] = (line[i] + predictor) & 0xFF
        else:
            raise Failure(f"unknown PNG filter {kind}")


def stop_orphan_microvm() -> None:
    """Make sure a microVM the application left behind is **not** left behind.

    A step that fails while the application is still starting can leave a guest running with the
    root disk held, so the next run would meet a locked image instead of a test.

    On this path there is **no control socket to ask**: the hypervisor's own process dies with
    the application (`PR_SET_PDEATHSIG`, `fc-run`), which is the project's own rule that a child is
    never an orphan.  So what this does is *verify*
    that: a Firecracker process that is still there after its application is gone would be a real
    bug (a leak), and the test says so instead of hiding it — never a signal, and never a guess.
    """
    leftovers = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # `comm` is the process's own name, and it is bounded, unlike a command line.
            if (entry / "comm").read_text().strip() == "firecracker":
                leftovers.append(int(entry.name))
        except OSError:
            continue
    if leftovers:
        raise Failure(
            "a Firecracker process outlived its application "
            f"({leftovers}): the child is supposed to die with the parent"
        )


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="the desktop-cracker system test")
    parser.add_argument("--only", default="", help="run only these steps (comma-separated)")
    parser.add_argument("--skip", default="", help="skip these steps (comma-separated)")
    parser.add_argument("--list", action="store_true", help="print the step names and exit")
    parser.add_argument("--run-dir", default="", help="where the run's own files go")
    args = parser.parse_args()

    if args.list:
        for name, _ in STEPS:
            print(name)
        return 0

    only = [s for s in args.only.split(",") if s]
    skip = [s for s in args.skip.split(",") if s]
    for name in only + skip:
        if name not in [step for step, _ in STEPS]:
            print(f"system-tests: no step is called {name!r}", file=sys.stderr)
            return 2
    chosen = [
        (name, fn)
        for name, fn in STEPS
        if (not only or name in only) and name not in skip
    ]

    if not APP.exists():
        print(f"system-tests: {APP} is not built (run `make build`)", file=sys.stderr)
        return 2
    if not PLUGIN.exists():
        print(f"system-tests: {PLUGIN} is not built (run `make build`)", file=sys.stderr)
        return 2
    if not os.access("/dev/kvm", os.R_OK):
        print("system-tests: /dev/kvm is not readable: no microVM can run here", file=sys.stderr)
        return 2

    # **The passphrase comes from the person**, never from a file, never from the environment.
    # It is only asked when a step will actually open the disk: `--only`/`--skip` may leave the
    # pass with nothing that needs it (`--only no-plugin-is-the-normal-run` is a pass of its own).
    needs_the_disk = any(name != "no-plugin-is-the-normal-run" for name, _ in chosen)
    password = getpass.getpass("root disk passphrase: ") if needs_the_disk else ""
    if needs_the_disk and not password:
        print("system-tests: no passphrase given", file=sys.stderr)
        return 2

    # **The workspace's own `temp/`**, never the system's `/tmp`: a test's scratch belongs beside
    # the project it is testing (`AGENTS.md`), and the run's plumbing (its sockets, the guest's
    # control share) is all that ever appears there.
    run_dir = Path(args.run_dir) if args.run_dir else ROOT / "temp/system-test"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)

    passed = failed = skipped = 0
    needs_boot = any(name != "boot-and-wrong-password" for name, _ in chosen)
    run = Run(run_dir, free_port(), CONFIG)
    if any(name == "ssh" for name, _ in chosen):
        # The port the pass forwards to the guest's sshd (`--ssh-port`), on the host's loopback.
        run.ssh_port = free_port()
    if any(name == "additional-disks" for name, _ in chosen):
        # **Two tiny disks of the test's own** (the operator: "during your system-tests you can
        # use very small empty disks, just enough to check the feature"): one plain filesystem
        # and one LUKS container — the two shapes the guest's tool has to handle.  They are made
        # in the pass's own directory and deleted with it; the run's root disk is untouched.
        run.disks = make_test_disks(run_dir / "disks")

    try:
        for name, fn in chosen:
            if name == "boot" and not needs_boot:
                print(f"──── {name}: skipped (nothing after it needs the boot)")
                skipped += 1
                continue
            print(f"──── {name}", flush=True)
            started = time.time()
            try:
                fn(run, password)
            except Closed as closed:
                print(f"FAIL {name}: the application is gone ({closed})")
                failed += 1
                print(f"      status: {json.dumps(safe_status(run))}")
                print(f"      output: {' | '.join(run.stdout[-6:])}")
            except Failure as failure:
                print(f"FAIL {name}: {failure}")
                failed += 1
                print(f"      events: {json.dumps(run.events[-8:])}")
                print(f"      status: {json.dumps(safe_status(run))}")
                print(f"      frame:  {safe_frame(run)}")
                print(f"      output: {' | '.join(run.stdout[-8:])}")
            except (TimeoutError, urllib.error.URLError, OSError) as error:
                print(f"FAIL {name}: {error}")
                failed += 1
                print(f"      events: {json.dumps(run.events[-8:])}")
                print(f"      status: {json.dumps(safe_status(run))}")
                print(f"      frame:  {safe_frame(run)}")
            else:
                print(f"ok   {name} ({time.time() - started:.1f}s)")
                passed += 1
    finally:
        if run.process is not None and not run.exited():
            rc = run.stop()
            print(f"──── the application exited with {rc}", flush=True)
        else:
            # The application is gone: anything it left behind is looked for, so the disk is free
            # for the next run (`stop_orphan_microvm`).
            stop_orphan_microvm()
        # **The application must not have written into the test's own directory**: the only
        # things in it are the run's plumbing (its sockets and the guest's control share).
        # The pass's **own** disks (`additional-disks` makes two 16 MiB images under
        # `disks/`) are the test's, not the application's: the operator's rule is that a
        # test's disks are small, and this check is about what the *application* wrote.
        # **A finished run leaves nothing behind**: every
        # directory this pass's runs kept their sockets in is gone.  The application removes it on
        # the way out it actually took — the window closed, the disk refused, a signal — and a
        # leftover here is a leak, not a detail: it is a socket file of a dead process sitting in the
        # user's runtime directory.
        left = [str(d) for d in run.run_dirs if d.exists()]
        if left:
            print(
                f"note: the run left its socket director"
                f"{'y' if len(left) == 1 else 'ies'} behind: {left} "
                f"(a finished run removes <runtime base>/run-<pid>)",
                flush=True,
            )
        own_disks = (run_dir / "disks").resolve()
        leftovers = sorted(
            str(p.relative_to(run_dir))
            for p in run_dir.rglob("*")
            if p.is_file() and own_disks not in p.resolve().parents
        )
        unexpected = [
            name
            for name in leftovers
            if not name.endswith(".sock") and "control" not in str(name)
        ]
        if unexpected:
            print(f"note: the run left {unexpected} in {run_dir} (it should write no file)")
        run.close()

    print(
        f"system-tests: {passed} passed, {failed} failed, {skipped} skipped", flush=True
    )
    return 1 if failed else 0


def safe_status(run: Run) -> dict:
    try:
        return run.status()
    except Exception as error:  # the plugin is gone with the application
        return {"error": str(error)}


def safe_frame(run: Run) -> str:
    """A frame described for a failure's message, or why there is none."""
    try:
        width, height, colours, mean = describe_png(run.frame())
        return f"{width}x{height}, {colours} colours, mean {mean:.1f}"
    except NotDrawn:
        return "no frame: nothing has been drawn yet"
    except Exception as error:
        return f"no frame: {error}"


if __name__ == "__main__":
    sys.exit(main())
