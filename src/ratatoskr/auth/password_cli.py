"""``ratatoskr hash-password``: read a password without echo (or from stdin) and print its argon2id hash."""

from __future__ import annotations

import getpass
from collections.abc import Callable
from typing import BinaryIO, TextIO

from ratatoskr.auth.identity.local import hash_password


def _read_piped_line(stdin: TextIO) -> str:
    """First line of piped input. The raw bytes are read as UTF-8 (a BOM is dropped) whatever the console code page
    is, so a password piped on Windows hashes the same as one typed on Linux. Raises ``UnicodeDecodeError``."""
    buffer: BinaryIO | None = getattr(stdin, "buffer", None)
    line = buffer.readline().decode("utf-8") if buffer is not None else stdin.readline()
    return line.removeprefix("﻿").rstrip("\r\n")


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
        try:
            password = _read_piped_line(stdin)
        except UnicodeDecodeError:
            print("Input is not valid UTF-8.", file=stderr)
            return 1
    if not password:
        print("Password must not be empty.", file=stderr)
        return 1
    print(hash_password(password), file=stdout)
    return 0
