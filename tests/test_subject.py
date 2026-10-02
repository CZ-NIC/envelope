from envelope import Envelope
from helpers import MESSAGE, assert_lines


def test_cache_recreation():
    first, second = "Test", "Another"
    e = Envelope(MESSAGE).subject(first)
    assert_lines(e, f"Subject: {first}")

    e.subject(second)
    assert_lines(e, f"Subject: {second}")
