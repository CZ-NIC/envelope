import logging
from base64 import b64encode

import pytest

from envelope import Envelope
from envelope.constants import AUTO
from helpers import MESSAGE, TEXT_ATTACHMENT, assert_lines

LONG_TEXT = "Longer than thousand chars. " * 1000
PLAIN_HEADERS = ('Content-Type: text/plain; charset="utf-8"',)
HTML_HEADERS = ('Content-Type: text/html; charset="utf-8"',)


def test_message_generating():
    assert_lines(Envelope(MESSAGE).subject("my subject").send(False),
                 "Subject: my subject", MESSAGE, min_lines=10)


def test_short_message_is_7bit():
    assert_lines(Envelope().message("short text").subject("my subject").send(False),
                 'Content-Type: text/plain; charset="utf-8"',
                 'Content-Transfer-Encoding: 7bit',
                 "Subject: my subject",
                 "short text", min_lines=10)


def test_1000_split():
    """ Lines longer than 1000 chars: the encoding should be no more 7bit but base64
    (or quoted-printable which is however not guaranteed). """
    e = Envelope().message(LONG_TEXT).subject("my subject").send(False)
    text = assert_lines(e,
                        'Content-Type: text/plain; charset="utf-8"',
                        "Content-Transfer-Encoding: base64",
                        "Subject: my subject",
                        min_lines=100,
                        absent='Content-Transfer-Encoding: 7bit')
    assert not any(len(line) > 999 for line in text.splitlines())


@pytest.fixture
def short_html_envelope():
    return Envelope().message("short text").message("<b>html</b>", alternative="html").subject("my subject")


def test_1000_split_html_both_7bit(short_html_envelope):
    assert_lines(short_html_envelope.send(False),
                 "Subject: my subject",
                 'Content-Type: text/plain; charset="utf-8"',
                 'Content-Transfer-Encoding: 7bit',
                 "short text",
                 'Content-Type: text/html; charset="utf-8"',
                 'Content-Transfer-Encoding: 7bit',
                 "<b>html</b>", min_lines=10)


def test_1000_split_html_plain_base64(short_html_envelope):
    e = short_html_envelope.copy().message(LONG_TEXT).send(False)
    assert_lines(e,
                 "Subject: my subject",
                 'Content-Type: text/plain; charset="utf-8"',
                 "Content-Transfer-Encoding: base64",
                 'Content-Type: text/html; charset="utf-8"',
                 'Content-Transfer-Encoding: 7bit',
                 "<b>html</b>", min_lines=100,
                 absent="short text")


def test_1000_split_html_html_base64(short_html_envelope):
    e = short_html_envelope.copy().message(LONG_TEXT, alternative="html").send(False)
    assert_lines(e,
                 "Subject: my subject",
                 'Content-Type: text/plain; charset="utf-8"',
                 'Content-Transfer-Encoding: 7bit',
                 'short text',
                 'Content-Type: text/html; charset="utf-8"',
                 "Content-Transfer-Encoding: base64", min_lines=100,
                 absent="<b>html</b>")


def test_1000_split_html_both_base64(short_html_envelope):
    e = short_html_envelope.copy().message(LONG_TEXT, alternative="html").message(LONG_TEXT).send(False)
    assert_lines(e,
                 "Subject: my subject",
                 'Content-Type: text/plain; charset="utf-8"',
                 "Content-Transfer-Encoding: base64",
                 'Content-Type: text/html; charset="utf-8"',
                 "Content-Transfer-Encoding: base64", min_lines=100,
                 absent=('Content-Transfer-Encoding: 7bit', 'short text', "<b>html</b>"))


def test_missing_message():
    assert Envelope().to("hello").preview() == ""


def test_contents_fetching():
    text = "Small sample text attachment.\n"
    with TEXT_ATTACHMENT.open() as f:
        e1 = Envelope(f)
        e2 = e1.copy()  # stays intact even if copied to another instance
        assert e1.message() == text
        assert e2.message() == text
    assert e2.copy().message() == text


def test_preview():
    assert_lines(Envelope(TEXT_ATTACHMENT).preview(),
                 'Content-Type: text/plain; charset="utf-8"',
                 "Subject: ",
                 "Small sample text attachment.")


def test_equality():
    source = {"message": "message", "subject": "hello"}
    e1 = Envelope(**source).date(False)
    e2 = Envelope(**source).date(False)
    assert e1 == e2
    assert str(e1) == e2
    assert bytes(e1) == e2

    s = ('Content-Type: text/plain; charset="utf-8"\nContent-Transfer-Encoding: 7bit'
         '\nMIME-Version: 1.0\nSubject: hello\n\nmessage\n')
    b = bytes(s, "utf-8")
    assert s == e1
    assert s == str(e1)
    assert b == e1
    assert b == bytes(e1)


def test_bcc_ignored():
    e = Envelope(message="message", subject="hello", cc="person-cc@example.com", bcc="person-bcc@example.com")
    assert "person-bcc@example.com" in e.recipients()
    assert_lines(e, 'Cc: person-cc@example.com', absent='Bcc: person-bcc@example.com')


def test_internal_cache():
    e = Envelope("message").date(False)  # Date might interfere with the Envelope objects equality
    e.header("header1", "1")

    # create cache under the hood
    assert not e._result
    e.as_message()["header1"]
    assert e._result

    # as soon as object changed, cache regenerated
    e.header("header2", "1")
    e2 = Envelope("message").header("header1", "1").header("header2", "1").date(False)
    assert e.as_message()["header2"] == "1"
    assert e2 == e
    assert_lines(e, "header2: 1")


def test_wrong_charset_message(caplog):
    raw = "ř".encode("cp1250")
    e = Envelope(raw)
    with pytest.raises(ValueError):
        str(e)
    with caplog.at_level(logging.WARNING, logger="envelope"):
        caplog.clear()
        repr(e)
    assert caplog.record_tuples == [
        ("envelope.message", logging.WARNING,
         "Cannot decode the message correctly, plain alternative bytes are not in Unicode.")]

    e.header("Content-Type", "text/plain; charset=cp1250")
    e.header("Content-Transfer-Encoding", "base64")
    e.message(b64encode(raw), alternative=AUTO)
    assert e.message() == "ř"
    # Strangely, putting apostrophes around the charset would not work


def test_repr():
    e = Envelope("hello").to("test@example.com")
    assert repr(e) == 'Envelope(to=[test@example.com], message="hello")'
