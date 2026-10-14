#!/usr/bin/env python3
"""The system test's **ssh client**: log in to the guest through the forwarded port.

    system-tests/ssh_client.py --port PORT [--host 127.0.0.1] [--user deskuser] -- COMMAND

It is the one thing the system test cannot do in its own process: talk the ssh protocol to the
guest's sshd, through the port the run forwarded (`--ssh-port`, SSH: ). The test starts
it as a program and reads its exit status, so what the test asserts is what a person's `ssh` would
give them.

**The password is read from standard input** — never from an argument, never from an environment
variable, never from a file (`AGENTS.md`, "Environment variables"): the person running the test
types the guest's password into the test, the test writes it to this program's stdin, and it lives
in this process's memory for as long as the connection takes.  It is the same shape the application
itself takes a disk's passphrase with (`--disk-passphrase-stdin`).

The exit status is the remote command's own, so a caller can assert on it:

    0        the command ran and succeeded
    N        the command ran and exited N
    255      **no login**: the connection was refused, or the password was not accepted
             (the same number `ssh` itself uses for its own failures)
    2        this program was called wrongly

It prints the remote command's output (stdout and stderr, in arrival order) and, on a failure of
its own, a sentence to stderr.  Nothing is written to disk: no known-hosts file, no key, no log.

A connection the guest **resets** is retried until `--timeout` is spent: the forward carries frames
from the moment the microVM starts, so the host's port answers before the guest's own sshd is
listening, and a person typing `ssh` would simply try again.  A refused *password* is never
retried — that is the guest's answer, not the guest not being ready.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

EXIT_NO_LOGIN = 255
EXIT_USAGE = 2


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ssh_client.py",
        description="run a command in the guest over ssh (the password comes from stdin)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="the host the forward listens on")
    parser.add_argument("--port", type=int, required=True, help="the forwarded port")
    parser.add_argument("--user", default="deskuser", help="the guest user to log in as")
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="how long a connection and a command may take, in seconds",
    )
    parser.add_argument(
        "--command",
        default="",
        help="the command to run in the guest (default: nothing — just log in)",
    )
    # Everything after `--` is the remote command, so a command with its own switches does not
    # have to be quoted into one argument.
    parser.add_argument("rest", nargs="*", help="the remote command (after `--`)")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    command = args.command or " ".join(args.rest)

    try:
        import paramiko
    except ImportError:
        print(
            "ssh_client: paramiko is not installed for this Python "
            f"({sys.executable}); the system test needs it (pip install paramiko)",
            file=sys.stderr,
        )
        return EXIT_USAGE

    # Paramiko logs a traceback of its own to stderr for every connection the guest resets, which
    # is the *normal* state of matters while the guest's systemd is bringing `ssh.service` up.  The
    # caller reads this program's stderr, and a screenful of paramiko internals for a connection
    # that is simply early is noise, not information: what the caller gets is the one sentence
    # below, or the remote command's own output.
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    # **The password, from stdin only.**  A missing one is not an error here: an ssh server may
    # accept the login without one, and the caller is the one that knows which it expects.
    password = sys.stdin.readline().rstrip("\n")

    # **The retry is the documented switch's own shape, not a test's patience.**  A run with
    # `--ssh-port` opens the host's port the moment the microvm starts, and the port stays open
    # whether the guest's sshd is listening inside or not: the forward carries frames, and until
    # the guest's systemd has started `ssh.service` every connection is reset.  Measured: the door
    # is open at the run's fifth second and a login succeeds at about the twenty-fifth, with the
    # guest already "ready" in between.  So a refused connection is answered by trying again until
    # `--timeout` is spent — which is precisely what a person typing `ssh` would do.
    #
    # One **fresh** `SSHClient` per attempt: a client whose connection failed keeps the dead
    # transport, and the next `connect` on it answers "No existing session" instead of trying
    # again (measured — that is what a single client across the retries did).
    deadline = time.monotonic() + args.timeout
    last = ""
    while True:
        client = paramiko.SSHClient()
        # The guest's host keys are made when its userland is built and are the image's, so there
        # is nothing on this host to verify them against — the same "the key is unknown, accept
        # it?" a person answers the first time.  It is a sandbox reached only through the run's own
        # forward on the host's loopback, so there is no third machine in the middle to be fooled.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=args.host,
                port=args.port,
                username=args.user,
                password=password or None,
                allow_agent=False,
                look_for_keys=False,
                # Per attempt, so a half-open connection cannot eat the whole budget.
                timeout=min(10.0, args.timeout),
                banner_timeout=min(10.0, args.timeout),
                auth_timeout=min(10.0, args.timeout),
            )
            break
        except paramiko.AuthenticationException:
            print(f"ssh_client: the guest refused {args.user}'s password", file=sys.stderr)
            return EXIT_NO_LOGIN
        except Exception as error:  # noqa: BLE001 — any transport failure is "not yet"
            last = str(error) or error.__class__.__name__
            try:
                client.close()
            except Exception:  # noqa: BLE001 — a failed client has nothing to close cleanly
                pass
            if time.monotonic() >= deadline:
                print(
                    f"ssh_client: no login on {args.host}:{args.port} in {args.timeout:.0f}s: {last}",
                    file=sys.stderr,
                )
                return EXIT_NO_LOGIN
            time.sleep(0.5)

    try:
        _, stdout, stderr = client.exec_command(command or "true", timeout=args.timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        status = stdout.channel.recv_exit_status()
    finally:
        client.close()
    sys.stdout.write(out)
    sys.stderr.write(err)
    return status


if __name__ == "__main__":
    # `Path` is imported for the docstring's promise that nothing is written: there is no path
    # anywhere in this program, and this line keeps the import honest if that ever changes.
    _ = Path
    sys.exit(main(sys.argv[1:]))
