from ratatoskr.backends.limits import clamp_text


def test_short_text_is_untouched() -> None:
    result = clamp_text("hello", 100, "hint")
    assert result.text == "hello"
    assert result.truncated is False


def test_long_text_is_cut_with_note_within_budget() -> None:
    result = clamp_text("x" * 5000, 1024, "Add a LIMIT.")
    assert result.truncated is True
    assert len(result.text.encode("utf-8")) <= 1024
    assert result.text.endswith("[Response truncated: it exceeded 1024 bytes. Add a LIMIT.]")


def test_cut_respects_utf8_boundaries() -> None:
    result = clamp_text("ğ" * 2000, 1024, "hint")
    result.text.encode("utf-8")  # must not raise
    assert result.truncated is True
    assert len(result.text.encode("utf-8")) <= 1024
