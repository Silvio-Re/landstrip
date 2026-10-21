#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

"""Verify executable-attached policies follow --cwd, unlike policy sources."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main(binary):
    binary = str(Path(binary).resolve(strict=True))
    checked = 0
    failures = []
    with tempfile.TemporaryDirectory(prefix="ls-executable-policy-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        caller, target = root / "caller", root / "execution"
        for directory in (caller, target):
            (directory / "bin").mkdir(parents=True)
        secret, public = root / "secret", root / "public"
        secret.write_text("private-content\n")
        public.write_text("readable-content\n")
        policy = {
            "filesystem": {"denyRead": [str(secret)], "allowWrite": ["/dev/null"]},
            "macos": {"allowPty": True},
        }
        invalid = {"unknownExecutablePolicyField": True}
        script = (
            "#!/bin/sh\n"
            f'/bin/cat "{public}" >/dev/null || exit 41\n'
            f'if /bin/cat "{secret}" >/dev/null 2>&1; then exit 42; fi\n'
            "printf 'target-policy-applied\\n'\n"
        )
        for directory in (caller, target):
            names = ("tool", "bin/tool", "only", "bin/only") if directory == target else (
                "tool", "bin/tool"
            )
            for name in names:
                executable = directory / name
                executable.write_text(script)
                executable.chmod(0o755)
                value = json.dumps(policy if directory == target else invalid)
                if sys.platform == "darwin":
                    subprocess.run(
                        ["/usr/bin/xattr", "-w", "user.landstrip.policy", value, str(executable)],
                        cwd=caller, env=os.environ.copy(), check=True, timeout=10,
                    )
                else:
                    os.setxattr(executable, "user.landstrip.policy", value.encode())
            (directory / "link").symlink_to("bin/tool")
            (directory / "bin/link").symlink_to("tool")
        (caller / "policy.json").write_text(json.dumps(policy))
        (target / "policy.json").write_text(json.dumps(invalid))
        cases = [
            ("./tool", "/bin"),
            ("bin/tool", "/bin"),
            ("tool", "bin"),
            ("tool", ""),
            ("tool", ":missing"),
            ("tool", "missing:"),
            ("tool", "missing::other"),
            (str(target / "tool"), "bin"),
            ("tool", str(target / "bin")),
            ("./link", "/bin"),
            ("bin/link", "/bin"),
            ("link", "bin"),
            ("./only", "/bin"),
            ("bin/only", "/bin"),
            ("only", "bin"),
            ("only", ""),
            ("/bin/sh", "/bin"),
        ]
        for tool, path in cases:
            env = {**os.environ, "PATH": path}
            source = ["--policy", "policy.json"] if tool == "/bin/sh" else []
            for action in ("run", "check", "resolve"):
                args = [binary, action, "--cwd", str(target), *source]
                args += ["--", tool] if action == "run" else ["--tool", tool]
                if action == "run" and source:
                    args.append(str(target / "tool"))
                result = subprocess.run(
                    args, cwd=caller, env=env, capture_output=True, text=True, timeout=15,
                )
                checked += 1
                try:
                    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
                    if action == "run":
                        assert result.stdout == "target-policy-applied\n", result.stdout
                    elif action == "check":
                        assert json.loads(result.stdout)["valid"] is True, result.stdout
                    else:
                        assert json.loads(result.stdout)["macos"]["allowPty"] is True, result.stdout
                except AssertionError as error:
                    failures.append(f"{action} {tool!r} PATH={path!r} policy={source!r}: {error}")
        assert not failures, "\n".join(failures)
    print(f"executable policy verified ({checked} cases)")


if __name__ == "__main__":
    main(sys.argv[1])
