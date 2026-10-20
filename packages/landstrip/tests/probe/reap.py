# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


def children(pid):
    return Path(f"/proc/{pid}/task/{pid}/children").read_text().split()


def wait_for(predicate, message, deadline):
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(0.01)


if sys.argv[1:] == ["children"]:
    print("ready", flush=True)
    input()
    parent = os.fork()
    if parent == 0:
        signal.signal(signal.SIGUSR1, lambda *_: os._exit(0))
        for _ in range(8):
            if os.fork() == 0:
                while True:
                    signal.pause()
        os._exit(0)
    assert os.waitpid(parent, 0) == (parent, 0)
    print("orphaned", flush=True)
    input()
    sys.exit(37)
else:
    binary, policy = sys.argv[1:]
    with subprocess.Popen(
        [binary, "run", "-p", policy, "--", sys.executable, __file__, "children"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as broker:
        try:
            deadline = time.monotonic() + 10
            assert select.select([broker.stdout], [], [], 10)[0], "tool did not become ready"
            assert broker.stdout.readline() == "ready\n"
            init, = children(broker.pid)
            main, = children(init)
            os.kill(int(init), signal.SIGSTOP)
            wait_for(
                lambda: Path(f"/proc/{init}/stat").read_text().rsplit(") ", 1)[1].startswith("T"),
                "init did not stop",
                deadline,
            )
            broker.stdin.write("\n")
            broker.stdin.flush()
            assert select.select([broker.stdout], [], [], max(0, deadline - time.monotonic()))[0], (
                "tool did not orphan children"
            )
            assert broker.stdout.readline() == "orphaned\n"
            wait_for(lambda: len(children(init)) == 9, "missing adopted children", deadline)
            orphans = [pid for pid in children(init) if pid != main]
            for index, pid in enumerate(orphans):
                os.kill(int(pid), signal.SIGUSR1 if index < 4 else signal.SIGKILL)
            wait_for(
                lambda: all(
                    Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].startswith("Z")
                    for pid in orphans
                ),
                "adopted children did not exit",
                deadline,
            )
            os.kill(int(init), signal.SIGCONT)
            wait_for(lambda: children(init) == [main], "init retained zombie children", deadline)
            assert broker.poll() is None
            broker.stdin.write("\n")
            broker.stdin.flush()
            assert broker.wait(timeout=max(0, deadline - time.monotonic())) == 37
        finally:
            if broker.poll() is None:
                broker.kill()
            broker.wait(timeout=5)
