import pytest

from envelope import Envelope
from envelope.constants import PLAIN
from helpers import (CHARSET, EML, EML_DIR, GROUP_RECIPIENT, IMAGE_FILE, INTERNATIONALIZED, INVALID_CHARACTERS,
                     INVALID_HEADERS, QUOPRI, UTF_HEADER)

INLINE_IMAGE = EML_DIR / "inline_image.eml"


def test_load_from_string():
    assert Envelope.load("Subject: testing message").subject() == "testing message"


def test_load_file_contents():
    e = Envelope.load(EML.read_text())
    assert e.subject() == "Hello world subject"

    # multiple headers returned as list and in the same order
    assert len(e.header("Received")) == 2
    assert e.header("Received")[1][:26] == "from receiver2.example.com"


# NOTE Currently, no check is implemented that a mistaken path given as the contents raises.

def test_encoded_headers():
    e = Envelope.load(path=str(UTF_HEADER))
    assert e.subject() == "Re: text"
    assert e.from_() == "Jiří <jiri@example.com>"

    # header case-sensitive parsing in .header(): the output must be 'Subject: ...', not 'subject: ...'
    assert "Subject: Re: text" in str(e)


def test_long_encoded_address_header():
    """ When longer than certain number of characters, the method Parser.parse header.Header.encode()
    returned chunks that were problematic to parse with policy.header_store_parse. """
    address = Envelope.load("To: Novák Honza Name longer than 75 chars <honza.novak@example.com>").to()[0]
    assert address.address == "honza.novak@example.com"
    assert address.name == "Novák Honza Name longer than 75 chars"


def test_non_utf8_encoded_header():
    iso_2 = "Subject: =?iso-8859-2?Q?=BE=E1dost_o_blokaci_dom=E9ny?="
    assert Envelope.load(iso_2).subject() == "žádost o blokaci domény"


@pytest.mark.cli
def test_cli_loads_stdin(cli):
    assert "Hello world subject" in cli()


@pytest.mark.cli
def test_cli_displays_subject(cli):
    assert cli("--subject") == "Hello world subject"


@pytest.mark.cli
def test_cli_multiline_folded_header(cli):
    assert cli("--subject", stdin=QUOPRI) == \
        "Very long text Very long text Very long text Very long text Ver Very long text Very long text"


def test_alternative_and_related():
    e = Envelope.load(path=INLINE_IMAGE)
    assert e.message() == "Hi <img src='cid:image.gif'/>"
    assert e.subject() == "Inline image message"
    assert e.message(alternative=PLAIN) == "Plain alternative"
    assert bytes(e.attachments()[0]) == IMAGE_FILE.read_bytes()


@pytest.mark.cli
def test_cli_accessing_attachments(cli):
    # correctly preview the attachments
    assert cli("--attachments", stdin=INLINE_IMAGE) == "image.gif (image/gif): <img src='cid:True'/>"

    # correctly access the attachment, the bytes kept intact
    assert cli("--attachments", "image.gif", stdin=INLINE_IMAGE, decode=False) == IMAGE_FILE.read_bytes()


def test_another_charset():
    assert Envelope.load(CHARSET).message() == "Dobrý den"


def test_internationalized():
    assert Envelope.load(INTERNATIONALIZED).subject() == "Žluťoučký kůň"

    # when using preview, we do not want to end up with "Subject: =?utf-8?b?xb1sdcWlb3XEjWvDvSBrxa/FiA==?="
    # which could appear even when .subject() shows decoded version
    assert "Subject: Žluťoučký kůň" in Envelope.load(INTERNATIONALIZED).preview().splitlines()


def test_group_recipient():
    e = Envelope.load(GROUP_RECIPIENT)
    assert e.to() == []
    assert e.subject() == "From Alice Smith"

    assert Envelope.load("To: group: hi; group b: hi2;").recipients() == {"hi", "hi2"}


def test_invalid_characters(caplog):
    with caplog.at_level("WARNING", logger="envelope"):
        e = Envelope.load(INVALID_CHARACTERS)
    assert [(r.name, r.levelname, r.getMessage()) for r in caplog.records] == [(
        "envelope.parser", "WARNING",
        "Replacing some invalid characters in text/plain:"
        " 'utf-8' codec can't decode byte 0xe1 in position 1: invalid continuation byte")]

    text = 'V�\x17Een� z�kazn�ku!\n Va\x161e z�silka bude'
    assert e.message(alternative="plain")[:len(text)] == text
    html = '<HTML><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><BODY><P>Vážený'
    assert e.message()[:len(html)] == html

    # subject decoded from base64
    subject = "Vaše zásilka ceká na dorucení"
    assert e.subject() == subject

    # header lookup is case-insensitive and internationalized
    assert e.header("Subject") == subject
    assert e.header("subJEct") == subject
    assert e.header("dATe")[:3] == "Thu"


def test_invalid_headers(caplog):
    """ The file has some invalid headers whose parsing would normally fail. """
    with caplog.at_level("WARNING", logger="envelope"):
        e = Envelope.load(INVALID_HEADERS)
    assert [(r.name, r.levelname, r.getMessage()) for r in caplog.records] == [
        ("envelope.envelope", "WARNING",
         "Header List-Unsubscribe could not be successfully "
         "loaded with <mailto:RB��R@innovabrokers.com.co>: 'Header' object is not subscriptable"),
        ("envelope.parser", "WARNING",
         'Replacing some invalid characters in text/html: unknown encoding: "utf-8message-id: <123456@example.com>')]

    assert e.message() == "An invalid header"
    assert e.from_() == "Support Team <no_reply-2345@example.com>"
