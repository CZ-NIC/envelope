from envelope import Envelope
from envelope.constants import HTML, PLAIN
from helpers import IMAGE_FILE, TEXT_ATTACHMENT, assert_lines


def test_casting():
    e = Envelope().attach("hello", "text/plain").attach(b"hello bytes")

    # attachment data are fetched as bytes by default
    assert e.attachments()[0].data == b"hello" == bytes(e.attachments()[0])

    # attachment can be casted to string (default UTF-8 encoding)
    assert str(e.attachments()[0]) == "hello"

    # the same is valid if the input has already been in bytes
    assert e.attachments()[1].data == b"hello bytes" == bytes(e.attachments()[1])
    assert str(e.attachments()[1]) == "hello bytes"


def test_different_argument_order():
    path = TEXT_ATTACHMENT
    e = Envelope() \
        .attach(path, "text/csv", "foo") \
        .attach(mimetype="text/csv", name="foo", path=path) \
        .attach(path, "foo", "text/csv") \
        .attach([(path, "text/csv", "foo")]) \
        .attach(((path, "text/csv", "foo"),))
    model = repr(e.attachments()[0])
    # a tuple with a single attachment (and its details)
    e2 = Envelope(attachments=(path, "text/csv", "foo"))
    # a list that contains multiple attachments
    e3 = Envelope(attachments=[(path, "text/csv", "foo"), (path, "text/csv", "foo")])
    attachments = e.attachments() + e2.attachments() + e3.attachments()
    assert len(attachments) == 5 + 1 + 2
    assert all(model == repr(a) for a in attachments)


# --- inline images ---

NAME = IMAGE_FILE.name
SINGLE_ALTERNATIVE = ("Content-Type: multipart/related;",
                      "Subject: Inline image message",
                      'Content-Type: text/html; charset="utf-8"')
IMG_MSG = ("Content-Disposition: inline",
           "R0lGODlhAwADAKEDAAIJAvz9/v///wAAACH+EUNyZWF0ZWQgd2l0aCBHSU1QACwAAAAAAwADAAAC")
IMAGE_GIF = ("Hi <img src='cid:image.gif'/>", "Content-Type: image/gif", "Content-ID: <image.gif>", *IMG_MSG)
MULTIPLE_ALTERNATIVES = ('Content-Type: text/plain; charset="utf-8"',
                         "Plain alternative",
                         "Content-Type: multipart/related;",
                         'Content-Type: text/html; charset="utf-8"')


def new_envelope():
    return Envelope().subject("Inline image message")


def test_inline_only_html_alternative_specified():
    e = new_envelope().message(f"Hi <img src='cid:{NAME}'/>", alternative=HTML).attach(IMAGE_FILE, inline=True)
    assert_lines(e, *SINGLE_ALTERNATIVE, *IMAGE_GIF)


def test_inline_html_alternative_not_specified():
    e = new_envelope().message(f"Hi <img src='cid:{NAME}'/>").attach(path=IMAGE_FILE.absolute(), inline=True)
    assert_lines(e, *SINGLE_ALTERNATIVE, *IMAGE_GIF)


def test_inline_two_alternatives_plain_specified():
    e = new_envelope().message(f"Hi <img src='cid:{NAME}'/>") \
        .message("Plain alternative", alternative=PLAIN, boundary="bound") \
        .attach(IMAGE_FILE, inline=True)
    assert_lines(e,
                 'Content-Type: multipart/alternative; boundary="bound"',
                 "Subject: Inline image message",
                 "--bound",
                 *MULTIPLE_ALTERNATIVES,
                 *IMAGE_GIF)


def test_inline_two_alternatives_html_specified():
    e = new_envelope().message(f"Hi <img src='cid:{NAME}'/>", alternative=HTML).message("Plain alternative") \
        .attach(path=IMAGE_FILE.absolute(), inline=True)
    assert_lines(e,
                 "Content-Type: multipart/alternative;",
                 "Subject: Inline image message",
                 *MULTIPLE_ALTERNATIVES,
                 *IMAGE_GIF)


def test_inline_custom_cid():
    e = new_envelope().message("Hi <img src='cid:custom-name.jpg'/>") \
        .attach(path=IMAGE_FILE.absolute(), inline="custom-name.jpg")
    assert_lines(e,
                 *SINGLE_ALTERNATIVE,
                 "Hi <img src='cid:custom-name.jpg'/>",
                 "Content-Type: image/gif",
                 "Content-ID: <custom-name.jpg>",
                 *IMG_MSG)


def test_inline_cid_from_name_when_contents_given():
    e = new_envelope().message("Hi <img src='cid:filename.gif'/>") \
        .attach(IMAGE_FILE.read_bytes(), name="filename.gif", inline=True)
    assert_lines(e,
                 *SINGLE_ALTERNATIVE,
                 "Hi <img src='cid:filename.gif'/>",
                 "Content-Type: image/gif",
                 "Content-ID: <filename.gif>",
                 *IMG_MSG)


def test_inline_custom_cid_overrides_name_when_contents_given():
    e = new_envelope().message("Hi <img src='cid:custom-name.jpg'/>") \
        .attach(IMAGE_FILE.read_bytes(), name="filename.jpg", inline="custom-name.jpg")
    assert_lines(e,
                 *SINGLE_ALTERNATIVE,
                 "Hi <img src='cid:custom-name.jpg'/>",
                 "Content-Type: image/gif",
                 "Content-ID: <custom-name.jpg>",
                 *IMG_MSG)
