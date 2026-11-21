"""``ratatoskr hash-password``: read a password without echo (or from stdin) and print its argon2id hash."""

from __future__ import annotations

import getpass
from collections.abc import Callable
from typing import TextIO

from ratatoskr.auth.identity.local import hash_password


def run_hash_password(
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    if stdin.isatty():
        password = prompt("Password: ")
        if prompt("Repeat password: ") != password:
            print("Passwords do not match.", file=stderr)
            return 1
    else:
        password = stdin.readline().rstrip("\r\n")
    if not password:
        print("Password must not be empty.", file=stderr)
        return 1
    print(hash_password(password), file=stdout)
    return 0
