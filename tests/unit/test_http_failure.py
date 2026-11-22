import httpx

from ratatoskr.backends.http.failure import describe_failure

TENANT = "team-SECRET-42"
TOKEN = "tok-VALUE-never-shown"


def _chain() -> httpx.LocalProtocolError:
    """httpx wraps httpcore, which wraps h11: every level quotes the refused header value."""
    h11_error = type("LocalProtocolError", (Exception,), {})(f"Illegal header value b'{TENANT}\\n'")
    outer = httpx.LocalProtocolError(f"Illegal header value b'{TENANT}\\n'")
    outer.__cause__ = h11_error
    return outer


def test_local_protocol_errors_are_named_but_their_text_is_withheld() -> None:
    text = describe_failure(_chain(), secrets=[TENANT])
    assert text == (
        "LocalProtocolError (message withheld: it can quote request headers) <- "
        "LocalProtocolError (message withheld: it can quote request headers)"
    )


def test_other_messages_are_kept_without_configured_secrets() -> None:
    error = httpx.ConnectError(f"[Errno 111] refused; saw {TOKEN}, {TENANT} and Authorization: Bearer abc")
    text = describe_failure(error, secrets=[TOKEN, TENANT, ""])
    assert text.startswith("ConnectError: [Errno 111] refused; saw <secret>, <secret> and Authorization: ")
    assert TOKEN not in text and TENANT not in text and "abc" not in text


def test_unicode_errors_are_withheld() -> None:
    error = UnicodeEncodeError("ascii", f"{TENANT}\u00e9", 14, 15, "ordinal not in range(128)")
    assert describe_failure(error, secrets=[]) == "UnicodeEncodeError (message withheld: it can quote request headers)"


def test_the_chain_follows_cause_then_context_and_stops() -> None:
    try:
        try:
            raise KeyError("inner")
        except KeyError:
            raise ValueError("middle") from None
    except ValueError as middle:
        outer = RuntimeError("outer")
        outer.__context__ = middle
    assert describe_failure(outer, secrets=[]) == "RuntimeError: outer <- ValueError: middle"  # context suppressed
    loop = RuntimeError("loop")
    loop.__cause__ = loop
    assert describe_failure(loop, secrets=[]) == "RuntimeError: loop"


def test_long_messages_are_cut() -> None:
    text = describe_failure(httpx.ConnectError("x" * 5000), secrets=[])
    assert len(text) < 400
    assert text.endswith("…")
