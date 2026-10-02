import pytest

from envelope import Envelope
from helpers import CLI_CMD, IDENTITY_1, IDENTITY_2, TEXT_ATTACHMENT, run_subprocess

pytestmark = pytest.mark.cli


def test_bcc_shown_in_preview_only(cli):
    assert "Bcc: person@example.com" in cli("--bcc", "person@example.com", "--preview")
    assert "person@example.com" not in cli("--bcc", "person@example.com", "--send", "off")


def test_attachment_preview_and_send(cli):
    preview_text = "Attachment generic.txt (text/plain): Small sample text at..."
    assert preview_text in cli("--attach", TEXT_ATTACHMENT, "--preview")

    output = cli("--attach", TEXT_ATTACHMENT, "--send", "0")
    assert preview_text not in output
    assert 'Content-Disposition: attachment; filename="generic.txt"' in output


@pytest.fixture
def encrypted_subject(cli, gpg_home):
    """ Return a function (subject, subject_encrypted) -> (encrypted message, decrypted message). """

    def get(subject, subject_encrypted):
        ref = cli("--attach", TEXT_ATTACHMENT, "--send", "0",
                  "--gpg", gpg_home,
                  "--to", IDENTITY_2,
                  "--from", IDENTITY_1,
                  "--encrypt",
                  "--subject", subject,
                  "--subject-encrypted", subject_encrypted, stdin="text")
        # remove text "Have not been sent ... Encrypted subject: ..." prepended by ._send_now
        ref = ref[ref.index("\n\n") + 2:]
        return ref, Envelope.load(ref).as_message().as_string()

    return get


@pytest.mark.gpg
def test_subject_encrypted_custom_text(encrypted_subject):
    encrypted, decrypted = encrypted_subject("Hello world", "Good bye sun")
    assert "Subject: Good bye sun" in encrypted
    assert "Hello world" not in encrypted
    assert "Subject: Hello world" in decrypted
    assert "Good bye sun" not in decrypted


@pytest.mark.gpg
@pytest.mark.parametrize("value", ["False", "FALSE", "0", "oFF"])
def test_subject_encrypted_disabled(encrypted_subject, value):
    encrypted, decrypted = encrypted_subject("Hello world", value)
    assert "Subject: Hello world" in encrypted
    assert "Subject: Hello world" in decrypted


@pytest.mark.gpg
@pytest.mark.parametrize("value", ["True", "TRUE", "1", "oN"])
def test_subject_encrypted_default_placeholder(encrypted_subject, value):
    encrypted, decrypted = encrypted_subject("Hello world", value)
    assert "Subject: Encrypted message" in encrypted  # default text used by the library
    assert "Subject: Hello world" in decrypted


def test_real_entry_point_preview():
    output = run_subprocess(*CLI_CMD, "--bcc", "person@example.com", "--preview", stdin="hello")
    assert "Bcc: person@example.com" in output


def test_real_entry_point_send_simulation():
    output = run_subprocess(*CLI_CMD, "--attach", TEXT_ATTACHMENT, "--send", "0", stdin="hello")
    assert 'Content-Disposition: attachment; filename="generic.txt"' in output
