#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

"""Exercise path-based trap transport without inherited socket plumbing."""

import json
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


def run(binary, directory, policy, command, action="deny", inherited=None):
    policy_path = directory / "policy.json"
    policy_path.write_text(json.dumps(policy))
    socket_path = directory / "trap.sock"
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(10)
        args = [binary, "run", "--trap", str(socket_path), "-p", str(policy_path)]
        pass_fds = ()
        if inherited is not None:
            pass_fds = (inherited.fileno(),)
            args += ["--inherit", str(inherited.fileno())]
        with subprocess.Popen(
            args + ["--"] + command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
        ) as process:
            try:
                records = []
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    with connection.makefile("rb") as stream:
                        for line in stream:
                            trap = json.loads(line)
                            records.append(trap)
                            if trap.get("state") == "query":
                                response = {"query_id": trap["query_id"], "action": action}
                                connection.sendall((json.dumps(response) + "\n").encode())
                stdout, stderr = process.communicate(timeout=10)
                return process.returncode, stdout, stderr, records
            except BaseException:
                process.kill()
                process.communicate()
                raise


def main(binary):
    with tempfile.TemporaryDirectory(prefix="ls-trap-", dir="/tmp") as temporary:
        directory = Path(temporary)
        policy = {
            "filesystem": {"allowRead": ["/"], "allowWrite": ["/dev/null", str(directory / "kept")]}
        }
        # Only the explicitly inherited file may survive exec, not the trap socket.
        with (directory / "kept").open("w") as inherited:
            fd = inherited.fileno()
            shell = (
                'for fd in 3 4 5 6 7 8 9; do '
                f'if test "$fd" != {fd}; then '
                'if ( eval "printf leaked >&$fd" ) 2>/dev/null; then exit 1; fi; '
                'fi; done; '
                f'printf kept >&{fd}'
            )
            code, _, stderr, records = run(
                binary, directory, policy, ["/bin/sh", "-c", shell], inherited=inherited
            )
            assert code == 0, stderr
            assert not records, records
        assert (directory / "kept").read_text() == "kept"

        code, _, _, records = run(binary, directory, policy, [str(directory / "missing")])
        assert code != 0
        assert any(trap.get("code") == "LAUNCH_FAILED" for trap in records), records

        if sys.platform == "linux":
            secret = directory / "secret"
            secret.write_text("private-content")
            policy["filesystem"]["denyRead"] = [str(secret)]
            for action in ("deny", "allow"):
                code, stdout, stderr, records = run(
                    binary, directory, policy, ["/bin/cat", str(secret)], action=action
                )
                assert any(trap.get("state") == "query" for trap in records), records
                if action == "allow":
                    assert code == 0 and stdout == b"private-content", (code, stdout, stderr)
                else:
                    assert code != 0 and b"private-content" not in stdout
            policy["filesystem"]["denyReadAlways"] = [str(secret)]
            code, stdout, _, records = run(
                binary, directory, policy, ["/bin/cat", str(secret)], action="allow"
            )
            assert code != 0 and b"private-content" not in stdout
            assert records and all(trap.get("state") != "query" for trap in records), records
    print("trap socket verified")


if __name__ == "__main__":
    main(sys.argv[1])
