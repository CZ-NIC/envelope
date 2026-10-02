from pathlib import Path

import pytest

from envelope import Envelope
from envelope.utils import get_mimetype
from helpers import assert_lines, GPG_RING, IMAGE_FILE

PLAIN = """First
Second
Third
    """

HTML = """First<br>
Second
Third
    """

HTML_WITHOUT_LINE_BREAK = """<b>First</b>
Second
Third
    """

MIME_PLAIN = 'Content-Type: text/plain; charset="utf-8"'
MIME_HTML = 'Content-Type: text/html; charset="utf-8"'


@pytest.mark.parametrize("envelope", [
    lambda: Envelope().message(PLAIN).mime("plain", "auto"),
    lambda: Envelope().message(PLAIN),
    lambda: Envelope().message(HTML).mime("plain"),
], ids=["plain-auto", "plain-detected", "html-forced-plain"])
def test_plain(envelope):
    assert_lines(envelope(), MIME_PLAIN)


@pytest.mark.parametrize("envelope", [
    lambda: Envelope().message(PLAIN).mime("html", "auto"),
    lambda: Envelope().message(HTML),
    lambda: Envelope().message(HTML_WITHOUT_LINE_BREAK),
], ids=["html-forced", "html-detected", "html-without-line-break"])
def test_html(envelope):
    assert_lines(envelope(), MIME_HTML)


@pytest.mark.parametrize(("envelope", "line"), [
    # there already is a <br> tag so nl2br "auto" should not convert it
    (lambda: Envelope().message(HTML), "Second"),
    (lambda: Envelope().message(HTML).mime(nl2br=True), "Second<br>"),
    (lambda: Envelope().message(HTML_WITHOUT_LINE_BREAK), "Second<br>"),
    # nl2br disabled in "plain"
    (lambda: Envelope().message(HTML_WITHOUT_LINE_BREAK).mime("plain", True), "Second"),
    (lambda: Envelope().message(HTML_WITHOUT_LINE_BREAK).mime(nl2br=False), "Second"),
], ids=["html-with-br-auto", "html-with-br-forced", "no-br-auto", "plain-ignores-nl2br", "no-br-disabled"])
def test_nl2br(envelope, line):
    assert_lines(envelope(), line)


def test_alternative():
    boundary = "=====envelope-test===="

    # alternative="auto" can become both "html" and "plain"
    e1 = Envelope().message("He<b>llo</b>").message("Hello", alternative="plain", boundary=boundary).date(False)
    e2 = Envelope().message("He<b>llo</b>", alternative="html").message("Hello", boundary=boundary).date(False)
    assert e1 == e2

    # HTML variant is always the last even if defined before plain variant
    assert_lines(e1, MIME_PLAIN, "Hello", MIME_HTML, "He<b>llo</b>")


def test_only_2_alternatives_allowed():
    e1 = Envelope().message("He<b>llo</b>").message("Hello", alternative="plain")
    # we can replace alternative
    e1.copy().message("Test").message("Test", alternative="plain")

    # but in the moment we set all three and call send or preview, we should fail
    with pytest.raises(ValueError):
        e1.copy().message("Test", alternative="html").preview()


def test_libmagic():
    """ Should pass with either python-magic or file-magic library installed on the system #25.
    CI runs this test on its own and expects it to fail when neither is installed. """
    # directly test get_mimetype layer
    assert get_mimetype(data=b"<!DOCTYPE html>hello") == "text/html"
    assert get_mimetype(path=IMAGE_FILE) == "image/gif"

    # test get_mimetype in the action while dealing attachments
    e = (Envelope()
         .attach("hello", "text/plain")
         .attach(b"hello bytes")
         .attach(Path(GPG_RING / "trustdb.gpg"))
         .attach(b"<!DOCTYPE html>hello")
         .attach("<!DOCTYPE html>hello")
         .attach(IMAGE_FILE))
    assert [a.mimetype for a in e.attachments()] == ["text/plain", "text/plain", "application/octet-stream",
                                                     "text/html", "text/html", "image/gif"]
