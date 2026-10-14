# -*- coding: utf-8 -*-
"""A soak **with a real desktop workload**: VLC playing a shared video, then Firefox.

    python3 tools/workload-soak.py            # ten minutes, the project's own config

It reports, every
15 s, whether the picture is still changing (the plugin's `/status` and `POST /frame`) and how far
behind the window is (`damage_waiting`, `damage_oldest_ms`), and it drives the guest only through
`ssh` — the way a person would.  `SOAK_SECONDS`, `SOAK_VIDEO`, `SOAK_FIREFOX=0` and `SOAK_PASS`
are its knobs.
"""
import base64, hashlib, json, os, socket, subprocess, sys, time, urllib.request, threading
from pathlib import Path

PORT = os.environ.get("SOAK_PORT", "8457")
RUN_SECONDS = os.environ.get("SOAK_SECONDS", "700")
SSH_PORT = os.environ.get("SOAK_SSH_PORT", "2223")
ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "target/release/desktop-cracker"
PLUGIN = ROOT / "target/release/libdesk_plugin.so"
CONFIG = ROOT / "temp/config.yml"
PASSWORD = os.environ.get("SOAK_PASS", "test")
VIDEO = os.environ.get("SOAK_VIDEO", "dog-example.mp4")

env = dict(os.environ)
env["DESK_PLUGIN_PORT"] = str(PORT)
env["DESK_FIRECRACKER"] = str(ROOT / "temp/download/firecracker")
p = subprocess.Popen([APP, "--config", str(CONFIG), "--plugin-path", str(PLUGIN), "--disk-passphrase-stdin",
                      "--ssh-port", SSH_PORT, "--run-seconds", RUN_SECONDS],
                     env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True, bufsize=1)
out = []
threading.Thread(target=lambda: [out.append(l.rstrip("\n")) for l in p.stdout], daemon=True).start()
p.stdin.write(PASSWORD + "\n"); p.stdin.flush(); p.stdin.close()

import websocket
ws = None
for _ in range(240):
    try:
        ws = websocket.create_connection(f"ws://127.0.0.1:{PORT}/ws", timeout=5); break
    except Exception:
        time.sleep(0.5)
if ws is None:
    raise SystemExit("the plugin never took a client")
answered = False

def pump(timeout=0.15):
    global answered
    try:
        ws.settimeout(timeout); raw = ws.recv()
    except Exception:
        return None
    try:
        event = json.loads(raw)
    except ValueError:
        return None
    if event.get("event") == "question" and not answered:
        answered = True
        ws.send(json.dumps({"answer": {"password": PASSWORD}, "id": event["id"]}))
        print(f"soak: answered the {event.get('kind')} question", flush=True)
    return event

def status():
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/status", timeout=10).read())

def frame():
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/frame", method="POST")
    return urllib.request.urlopen(req, timeout=30).read()

def ssh(command, timeout=90):
    r = subprocess.run([sys.executable, str(ROOT / "system-tests/ssh_client.py"),
                        "--port", SSH_PORT, "--user", "deskuser", "--timeout", str(timeout), "--", command],
                       input="changeme\n", capture_output=True, text=True, timeout=timeout + 30)
    return r.returncode, (r.stdout + r.stderr).strip()

t0 = time.time()
# Wait for the guest's session to be up (the desktop), then start the workload.
for _ in range(90):
    pump(); time.sleep(0.5)
    try:
        if status()["state"] == "running" and status()["frames"] > 5:
            break
    except Exception:
        pass
print(f"soak: the guest is up after {time.time()-t0:.0f}s", flush=True)

rc, where = ssh("id -u; echo '--- the shared folder, as this user:'; ls /mnt/share/share-Downloads 2>&1 | head -3", 60)
print(f"soak: share check rc={rc}\n{where}", flush=True)

print("soak: starting VLC on the shared video (on the guest's own display)", flush=True)
rc, said = ssh(f"export DISPLAY=:0 XAUTHORITY=~/.Xauthority; "
               f"nohup vlc --fullscreen --loop --no-video-title-show "
               f"/mnt/share/share-Downloads/{VIDEO} >/tmp/vlc.log 2>&1 & sleep 6; "
               f"pgrep -c vlc; tail -3 /tmp/vlc.log", 90)
print(f"soak: vlc rc={rc} {said}", flush=True)

# **Firefox after VLC**: the workload the operator named, on the same pass.
if os.environ.get("SOAK_FIREFOX", "1") == "1":
    print("soak: starting Firefox on a page", flush=True)
    rc, said = ssh("export DISPLAY=:0 XAUTHORITY=~/.Xauthority; "
                   "nohup firefox-esr https://www.youtube.com/watch?v=jNQXAC9IVRw "
                   ">/tmp/firefox.log 2>&1 & sleep 8; pgrep -c firefox", 120)
    print(f"soak: firefox rc={rc} {said}", flush=True)

last, frozen, worst = None, 0, 0
while time.time() - t0 < float(RUN_SECONDS) + 20:
    for _ in range(75):
        pump(); time.sleep(0.2)
    try:
        st = status()
    except Exception as e:
        print(f"[{time.time()-t0:6.0f}s] STATUS GONE: {e}", flush=True)
        break
    try:
        png = frame(); digest = hashlib.sha256(png).hexdigest()[:12]
    except Exception as e:
        digest = f"none({str(e)[:30]})"
    same = digest == last
    frozen = frozen + 15 if same else 0
    worst = max(worst, st.get("damage_waiting", 0))
    print(f"[{time.time()-t0:6.0f}s] state={st['state']:8s} frames={st['frames']:6d} "
          f"waiting={st.get('damage_waiting','?')} oldest_ms={st.get('damage_oldest_ms','?')} "
          f"frame={digest} {'SAME' if same else 'new'}"
          f"{'  FROZEN ' + str(int(frozen)) + 's' if frozen >= 45 else ''}", flush=True)
    last = digest
    if frozen >= 240:
        print("soak: THE PICTURE HAS NOT CHANGED FOR FOUR MINUTES", flush=True)
        break
print(f"soak: worst damage_waiting seen: {worst}", flush=True)
rc, text = ssh("echo alive; uptime | head -1; pgrep -c vlc; pgrep -c firefox", 60)
print(f"soak: guest ssh rc={rc}\n{text}", flush=True)
print("=== the application's own last lines (with the guest's console) ===", flush=True)
print("\n".join(out[-40:]), flush=True)
p.terminate()
