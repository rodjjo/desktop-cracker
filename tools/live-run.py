#!/usr/bin/env python3
"""A driver for my own live tests: the application, the plugin, and the passphrase typed by me.

It is *not* part of the project's test suite (the suite is one file, one boot: `system-tests.py`).
It exists because a person is not always in front of the machine, and the two things I need to do by
hand — answer the disk's question and take frames off the running application — are exactly what the
plugin is for.

    live-run.py --seconds 60 [--keep] [--config temp/config.yml] [--visible]

It types the passphrase into the application's own dialog over the plugin (the passphrase is a
command-line argument to *this* tool and never to the application), then samples `/status` and
`POST /frame` and says whether the frames are still arriving — the freeze this work is about.

Nothing is written to disk: the frames it pulls are analysed in memory (a few statistics), and the
run's own directory is the project's `temp/`.
"""
import argparse
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "target/release/desktop-cracker"
PLUGIN = ROOT / "target/release/libdesk_plugin.so"

import websocket  # noqa: E402  (only needed for the /ws channel)


class Plugin:
    """The plugin's own HTTP and WebSocket, as the run it."""

    def __init__(self, port: int, password: str):
        self.port = port
        self.password = password
        self.events = []
        self.questions = []
        self.ws = None
        self.thread = None

    def connect(self, timeout=30.0):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                self.ws = websocket.create_connection(
                    f"ws://127.0.0.1:{self.port}/ws", timeout=5
                )
                break
            except Exception as error:  # not listening yet
                last = error
                time.sleep(0.2)
        else:
            raise RuntimeError(f"the plugin never answered: {last}")
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while True:
            try:
                message = self.ws.recv()
            except Exception:
                return
            if not message:
                continue
            print("   ws  | " + message, flush=True)
            try:
                event = json.loads(message)
            except json.JSONDecodeError:
                continue
            self.events.append(event)
            if event.get("event") == "question":
                self.questions.append(event)
                answer = None
                if event.get("kind") == "disk-password":
                    answer = {"password": self.password}
                elif event.get("kind") == "unlock-password":
                    answer = {"password": "test"}
                if answer is not None:
                    self.send({"answer": answer, "id": event["id"]})

    def send(self, obj):
        if self.ws is not None:
            self.ws.send(json.dumps(obj))

    def get(self, path, timeout=10):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}{path}", timeout=timeout
        ) as answer:
            return answer.read()

    def status(self):
        return json.loads(self.get("/status"))

    def frame(self):
        """The picture the window is about to draw, as the plugin hands it out (`POST /frame`)."""
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/frame", data=b"", method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as answer:
                return answer.read()
        except urllib.error.HTTPError as error:
            if error.code == 409:
                return None
            raise

    def action(self, name):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/action",
            data=json.dumps({"action": name}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as answer:
            return json.loads(answer.read())


def png_signature(png: bytes):
    """A cheap fingerprint of a frame: its size and the CRC of its own pixels (no libraries)."""
    if not png or png[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    width = height = 0
    idat = b""
    pos = 8
    while pos + 8 <= len(png):
        length = int.from_bytes(png[pos : pos + 4], "big")
        kind = png[pos + 4 : pos + 8]
        body = png[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            width = int.from_bytes(body[0:4], "big")
            height = int.from_bytes(body[4:8], "big")
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + length
    return (width, height, zlib.crc32(idat))


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--password", default="test")
    parser.add_argument("--config", default=str(ROOT / "temp/config.yml"))
    parser.add_argument("--run-dir", default=str(ROOT / "temp/live/run"))
    parser.add_argument(
        "--visible",
        action="store_true",
        default=True,
        help="keep the window on screen (the default: GTK does not draw a hidden widget)",
    )
    parser.add_argument("--hidden", dest="visible", action="store_false")
    parser.add_argument("--sample-ms", type=int, default=200)
    # Where to keep the last picture the window drew, for a person to look at (it is the guest's
    # own screen: the check that what is drawn is what the guest drew).
    parser.add_argument("--save-frame", default="")
    # **A command to run inside the guest**, over the run's own `--ssh-port` (the documented
    # switch): the guest's user and password are the project's own (`desktop-cracker`/`changeme`), and the
    # display is the guest's own (`:0`).  It is how a full-screen video is played without a hand on
    # the keyboard.
    parser.add_argument("--guest-command", default="")
    parser.add_argument("--ssh-port", type=int, default=0)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    port = free_port()
    env = dict(os.environ)
    env["DESK_PLUGIN_PORT"] = str(port)
    argv = [
        str(APP),
        "--config",
        args.config,
        "--plugin-path",
        str(PLUGIN),
        "--numlock-held",
    ] + (["--ssh-port", str(args.ssh_port)] if args.ssh_port else [])
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    lines = []
    def _echo():
        for line in process.stdout:
            line = line.rstrip()
            lines.append(line)
            print("   app | " + line, flush=True)
    reader = threading.Thread(target=_echo, daemon=True)
    reader.start()

    guest = None
    if args.guest_command and args.ssh_port:
        def _guest():
            # The guest comes up after the machine does: wait for its own sshd rather than
            # guessing.
            deadline = time.time() + 120
            while time.time() < deadline:
                probe = subprocess.run(
                    ["bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{args.ssh_port}"],
                    capture_output=True,
                )
                if probe.returncode == 0:
                    break
                time.sleep(0.5)
            time.sleep(5)
            print(f"live-run: the guest's command: {args.guest_command}", flush=True)
            subprocess.run(
                [
                    "sshpass",
                    "-p",
                    "changeme",
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "-p",
                    str(args.ssh_port),
                    "deskuser@127.0.0.1",
                    args.guest_command,
                ],
                timeout=900,
            )

        guest = threading.Thread(target=_guest, daemon=True)

    plugin = Plugin(port, args.password)
    started = time.time()
    try:
        plugin.connect()
        print("live-run: the plugin is answering; waiting for the guest", flush=True)
        if guest is not None:
            guest.start()
        # The window is hidden by the plugin's own rule unless asked for.
        if args.visible:
            plugin.action("hide-or-show")
            for _ in range(60):
                if plugin.status().get("visible"):
                    print("live-run: the window is on screen", flush=True)
                    break
                time.sleep(0.5)
            else:
                print("live-run: the window never became visible", flush=True)
        # **A stall is measured on the run's own events, not on my polling.**  The plugin pushes a
        # `frame` event for every picture the path produces, and `/status` counts them: a picture
        # that stopped arriving is "the count stopped moving while the guest was known to be
        # drawing", and comparing PNGs 200 ms apart is a *different* question (a video holds the
        # same picture for several of its frames, which looks like a stall and is not one).
        last_events = 0
        last_count = -1
        last_move = time.time()
        stalls = 0
        while time.time() - started < args.seconds:
            time.sleep(args.sample_ms / 1000)
            try:
                status = plugin.status()
            except Exception as error:
                print(f"live-run: the status: {error}", flush=True)
                break
            events = sum(1 for e in plugin.events if e.get("event") == "frame")
            count = status.get("frames", 0)
            print(
                f"live-run: t={time.time() - started:6.1f}s produced={count} events={events} "
                f"waiting={status.get('damage_waiting')}",
                flush=True,
            )
            if events != last_events or count != last_count:
                last_events = events
                last_count = count
                last_move = time.time()
            elif time.time() - last_move > 10 and status.get("state") == "running":
                stalls += 1
                if stalls == 1 or stalls % 6 == 0:
                    print(
                        f"live-run: no new picture for {time.time() - last_move:.1f}s "
                        f"(frame events={events}, produced={count}, drawn={status.get('frames')}, "
                        f"waiting={status.get('damage_waiting')})",
                        flush=True,
                    )
            if int(time.time() - started) % 30 == 0:
                print(
                    f"live-run: t={time.time() - started:6.1f}s pictures={count} events={events} "
                    f"waiting={status.get('damage_waiting')} oldest={status.get('damage_oldest_ms')}ms",
                    flush=True,
                )
        elapsed = time.time() - started
        print(
            f"live-run: {last_count} picture(s) in {elapsed:.0f}s, "
            f"the last new one {time.time() - last_move:.1f}s ago",
            flush=True,
        )
        status = plugin.status()
        print(f"live-run: status {json.dumps(status)}", flush=True)
        print("live-run: the application's own lines:", flush=True)
        for line in lines[-60:]:
            print("   " + line, flush=True)
        # End it through its own interface: the plugin's own `exit` action.
        try:
            plugin.action("exit")
        except Exception:
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
        print(f"live-run: the application ended with {process.returncode}", flush=True)
        return 0 if len(frames) > 1 else 1
    finally:
        if process.poll() is None:
            process.kill()


if __name__ == "__main__":
    sys.exit(main())
