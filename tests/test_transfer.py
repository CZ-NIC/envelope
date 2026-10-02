import pytest

from envelope import Envelope
from helpers import QUOPRI

LONG_TEXT = "J'interdis aux marchands de vanter trop leurs marchandises." \
    " Car ils se font vite pédagogues et t'enseignent comme but ce qui n'est par essence qu'un moyen," \
    " et te trompant ainsi sur la route à suivre les voilà bientôt qui te dégradent," \
    " car si leur musique est vulgaire ils te fabriquent pour te la vendre une âme vulgaire."
QUOTED = "J'interdis aux marchands de vanter trop leurs marchandises. Car ils se font v=" \
    "\nite p=C3=A9dagogues et t'enseignent comme but ce qui n'est par essence qu'un =" \
    "\nmoyen, et te trompant ainsi sur la route =C3=A0 suivre les voil=C3=A0 bient=" \
    "\n=C3=B4t qui te d=C3=A9gradent, car si leur musique est vulgaire ils te fabriq=" \
    "\nuent pour te la vendre une =C3=A2me vulgaire."


def assert_quoted_message(e: Envelope):
    assert e.message() == LONG_TEXT
    assert LONG_TEXT in e.preview()  # when using preview, we receive original text
    output = str(e.send(False))  # but when sending, quoted text is got instead
    assert LONG_TEXT not in output
    assert QUOTED in output


def test_auto_quoted_printable():
    """ Envelope internally converts long lines to quoted-printable. """
    assert_quoted_message(Envelope().message(LONG_TEXT))


def test_load_quoted_printable():
    """ Envelope is able to load the text that is already quoted. """
    assert_quoted_message(Envelope.load(f"Content-Transfer-Encoding: quoted-printable\n\n{QUOTED}"))


@pytest.mark.cli
def test_cli_quoted_printable_file(cli):
    """ The text is already quoted in a file. As LONG_TEXT contains non-ASCII characters,
    it tests the program locale also. """
    assert cli("--message", stdin=QUOPRI) == LONG_TEXT


def test_load_base64():
    hello = "aGVsbG8gd29ybGQ="
    assert Envelope.load(f"\n{hello}").message() == hello
    assert Envelope.load(f"Content-Transfer-Encoding: base64\n\n{hello}").message() == "hello world"


def test_implanted_transfer_encoding():
    e = Envelope().header("Content-Transfer-Encoding", "quoted-printable").message(QUOTED)
    assert e.message() == LONG_TEXT

    # we replace Content-Transfer-Encoding and change the message
    original = "hello world"
    hello = "aGVsbG8gd29ybGQ="
    e = Envelope().header("Content-Transfer-Encoding", "base64").message(hello)
    assert e.message() == original

    # the user specified Content-Transfer-Encoding but left the message unencoded
    e2 = Envelope().header("Content-Transfer-Encoding", "base64").message(original)
    assert e2.message() == original
