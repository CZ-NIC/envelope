import logging
import re

import pytest

from envelope import Envelope
from envelope.smtp_handler import SMTPHandler
from helpers import (EML_DIR, GPG_KEYS, GPG_PASSPHRASE, IDENTITY_1, IDENTITY_1_GPG_FINGERPRINT,
                     IDENTITY_2, IDENTITY_3, MESSAGE, PGP_MESSAGE, assert_lines, run_subprocess)

pytestmark = pytest.mark.gpg

# Identity 1: no passphrase. Identity 2: passphrase GPG_PASSPHRASE. Identity 3: not in the testing keyring.
IDENTITY_2_FINGERPRINT = "3C8124A8245618D286CF871E94CE2905DB00CDB7"
KEY_1 = "envelope-example-identity@example.com.key"
KEY_2 = "envelope-example-identity-2@example.com.key"
KEY_1_RAW = "envelope-example-identity@example.com.bytes.key"
SIGNATURE_BEGIN = "-----BEGIN PGP SIGNATURE-----"
SIGNATURE_END = "-----END PGP SIGNATURE-----"
UNKNOWN_FROM = "envelope-example-identity-not-stated-in-ring@example.com"
UNKNOWN_ADDRESS = "envelope-unknown@example.com"


@pytest.fixture
def home(gpg_home) -> str:
    """ The shared (read-only usage!) testing keyring as the `str` envelope expects. """
    return str(gpg_home)


def import_key(ring: str, key_file: str, passphrase: str | None = None):
    """ Import a key from tests/fixtures/gpg_keys into the ring by signing with it (the way envelope auto-imports). """
    Envelope("just importer").gpg(ring).sign(GPG_KEYS / key_file, passphrase=passphrase)


@pytest.fixture
def make_ring(empty_gpg_home_factory):
    """ Factory: `make_ring(KEY_1, (KEY_2, GPG_PASSPHRASE))` returns a new keyring with the given keys imported. """
    def make(*keys: str | tuple[str, str]) -> str:
        ring = str(empty_gpg_home_factory())
        for key in keys:
            import_key(ring, *((key,) if isinstance(key, str) else key))
        return ring
    return make


def decrypts(eml: str, ring: str) -> bool:
    """ Is the message decipherable with the keys in the ring? """
    return Envelope.load(eml, gnupg_home=ring).message() == MESSAGE


def produced(e: Envelope) -> bool:
    """ Render the envelope first (like the old check_lines did), then tell whether it has a result.
    Note: bool() of a not yet rendered Envelope is False even when the rendering would succeed. """
    str(e)
    return bool(e)


def assert_warned(caplog, text: str):
    assert any(record.levelno == logging.WARNING and text in record.getMessage() for record in caplog.records), \
        f"Warning {text!r} not logged, got: {caplog.messages}"


# ---------------------------------------------------------------- signing

def test_gpg_sign(home):
    assert_lines(Envelope(MESSAGE).gpg(home).sign(), MESSAGE, SIGNATURE_BEGIN, SIGNATURE_END, min_lines=10)


def test_gpg_auto_sign_known_sender(home):
    # mail from IDENTITY_1 is in the ring
    assert_lines(Envelope(MESSAGE).gpg(home).from_(IDENTITY_1).sign("auto"),
                 MESSAGE, SIGNATURE_BEGIN, SIGNATURE_END, min_lines=10)


def test_gpg_auto_sign_unknown_sender_is_not_signed(home):
    e = Envelope(MESSAGE).gpg(home).from_(UNKNOWN_FROM).sign("auto")
    assert SIGNATURE_BEGIN not in str(e).splitlines()


def test_gpg_force_sign_without_key_uses_first_found_key(home):
    assert SIGNATURE_BEGIN in str(Envelope(MESSAGE).gpg(home).sign(True)).splitlines()


def test_gpg_force_sign_with_unknown_sender_fails(home):
    e = Envelope(MESSAGE).gpg(home).from_(UNKNOWN_FROM).signature(True)
    with pytest.raises(RuntimeError):
        str(e)


def test_gpg_sign_passphrase(home):
    e = (Envelope(MESSAGE).to(IDENTITY_2).gpg(home).from_(IDENTITY_1)
         .signature(IDENTITY_2_FINGERPRINT, GPG_PASSPHRASE))  # passphrase needed
    assert_lines(e, SIGNATURE_BEGIN, min_lines=10)


# ---------------------------------------------------------------- encrypting

@pytest.mark.cli
def test_gpg_encrypt_message(home):
    message = Envelope(MESSAGE).gpg(home).from_(IDENTITY_1).to(IDENTITY_2).encrypt()
    assert_lines(message, PGP_MESSAGE, min_lines=10)

    assert MESSAGE in run_subprocess("gpg", "--decrypt", stdin=str(message))


@pytest.mark.cli
def test_gpg_encrypt(home):
    e = str(Envelope(MESSAGE).to(IDENTITY_2).gpg(home).from_(IDENTITY_1).subject("dumb subject").encryption())

    assert_lines(e,
                 "Encrypted subject: dumb subject",
                 "Encrypted message: dumb message",
                 "Subject: Encrypted message",
                 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";',
                 "From: envelope-example-identity@example.com",
                 "To: envelope-example-identity-2@example.com",
                 absent="Subject: dumb subject", min_lines=10)

    lines = e.splitlines()
    message = "\n".join(lines[lines.index(PGP_MESSAGE):])
    assert_lines(run_subprocess("gpg", "--decrypt", stdin=message),
                 'Content-Type: multipart/mixed; protected-headers="v1";',
                 'Subject: dumb subject',
                 'Content-Type: text/plain; charset="utf-8"',
                 MESSAGE)


def test_gpg_auto_encrypt_known_sender_and_recipient(home):
    # mail `from` IDENTITY_1 is in the ring
    e = Envelope(MESSAGE).gpg(home).from_(IDENTITY_1).to(IDENTITY_1).encrypt("auto")
    assert_lines(e, PGP_MESSAGE, '-----END PGP MESSAGE-----', absent=MESSAGE, min_lines=10, max_lines=15)


def test_gpg_auto_encrypt_and_sign(home):
    e = Envelope(MESSAGE).gpg(home).from_(IDENTITY_1).to(IDENTITY_2).signature("auto").encrypt("auto")
    assert_lines(e, PGP_MESSAGE, '-----END PGP MESSAGE-----', absent=MESSAGE, min_lines=20)


@pytest.mark.parametrize(("from_", "to"), [
    (UNKNOWN_ADDRESS, IDENTITY_1),
    (IDENTITY_1, UNKNOWN_ADDRESS),
], ids=["unknown-sender", "unknown-recipient"])
def test_gpg_auto_encrypt_skipped_for_unknown_address(home, from_, to):
    e = Envelope(MESSAGE).gpg(home).from_(from_).to(to).encrypt("auto")
    assert_lines(e, MESSAGE, absent=PGP_MESSAGE, max_lines=2)


def test_gpg_force_encrypt_without_key_returns_empty(home):
    e = Envelope(MESSAGE).gpg(home).from_(IDENTITY_1).to(UNKNOWN_ADDRESS).encryption(True)
    assert_lines(e, max_lines=1)
    assert bool(e) is False


# ---------------------------------------------------------------- arbitrary encryption keys

def test_arbitrary_encrypt_only_for_recipient_not_sender(home, make_ring):
    """ Message encrypted for IDENTITY_1 only, not for the sender: decipherable only with the right key. """
    e1 = str(Envelope(MESSAGE).to(IDENTITY_1).gpg(home).from_(IDENTITY_2).subject("dumb subject")
             .encryption(IDENTITY_1).as_message())
    ring = make_ring()

    assert decrypts(e1, home)
    assert not decrypts(e1, ring)
    # importing other key does not help
    import_key(ring, KEY_2, GPG_PASSPHRASE)
    assert not decrypts(e1, ring)
    # importing the right key does help
    import_key(ring, KEY_1)
    assert decrypts(e1, ring)


def test_arbitrary_encrypt_multiple_recipients(home, make_ring):
    e2 = str(Envelope(MESSAGE).to(IDENTITY_1).gpg(home).from_(IDENTITY_3)
             .encryption([IDENTITY_1, IDENTITY_2]).as_message())

    assert not decrypts(e2, make_ring())
    assert decrypts(e2, make_ring((KEY_2, GPG_PASSPHRASE)))
    assert decrypts(e2, make_ring((KEY_1, GPG_PASSPHRASE)))


def test_arbitrary_encrypt_for_sender_only(home, make_ring):
    """ Message not encrypted for a recipient but for a sender only (for some unknown reason). """
    e3 = str(Envelope(MESSAGE).to(IDENTITY_2).gpg(home).from_(IDENTITY_1).encryption([IDENTITY_1]).as_message())

    assert not decrypts(e3, make_ring((KEY_2, GPG_PASSPHRASE)))  # a ring with only IDENTITY_2
    assert decrypts(e3, make_ring((KEY_1, GPG_PASSPHRASE)))  # a ring with IDENTITY_1


def test_arbitrary_encrypt_mixed_fingerprints_and_emails(home, make_ring):
    e3 = str(Envelope(MESSAGE)
             .to("envelope-example-identity-3@example.com, envelope-example-identity@example.com")
             .gpg(home).from_(IDENTITY_2).encryption([IDENTITY_2, IDENTITY_1_GPG_FINGERPRINT]).as_message())

    assert decrypts(e3, make_ring((KEY_2, GPG_PASSPHRASE), KEY_1))  # a ring with both
    assert decrypts(e3, make_ring((KEY_2, GPG_PASSPHRASE)))  # a ring with IDENTITY_2
    assert decrypts(e3, make_ring((KEY_1, GPG_PASSPHRASE)))  # a ring with IDENTITY_1
    assert not decrypts(e3, make_ring())  # a ring with none


@pytest.mark.parametrize("explicit", [True, False], ids=["explicit-decipherers", "implicit-decipherers"])
def test_arbitrary_encrypt_unknown_key_fails(home, caplog, explicit):
    # a generator is passed to .encryption to test it takes other iterables than a list
    e = Envelope(MESSAGE)
    e = e.encryption(x for x in [IDENTITY_3, IDENTITY_1_GPG_FINGERPRINT]) if explicit else e.encryption()
    with caplog.at_level(logging.WARNING, logger="envelope"):
        assert str(e.to(f"{IDENTITY_3}, {IDENTITY_1}").from_(IDENTITY_2).gpg(home).as_message()) == "None"

    assert_warned(caplog, f"Key for {IDENTITY_3} seems missing, see: GNUPGHOME={home} gpg --list-keys")
    assert "Signing/encrypting failed." in caplog.messages
    assert not any(f"Key for {IDENTITY_2} seems missing" in m for m in caplog.messages)


def test_arbitrary_encrypt_raw_key_in_a_set(make_ring):
    """ Import a raw unarmored key given among the recipients; the .encryption takes a set (not only a list). """
    ring = make_ring((KEY_2, GPG_PASSPHRASE))
    key1_raw = (GPG_KEYS / KEY_1_RAW).read_bytes()
    e4 = Envelope(MESSAGE).encryption({IDENTITY_2, key1_raw}).to(IDENTITY_3).from_(IDENTITY_2).gpg(ring).as_message()

    assert decrypts(e4, ring)
    assert decrypts(e4, make_ring((KEY_1, GPG_PASSPHRASE)))


@pytest.mark.cli
@pytest.mark.parametrize(("from_", "to", "encrypt", "valid"), [
    (IDENTITY_1, (IDENTITY_2,), (), True),
    (IDENTITY_1, (IDENTITY_2,), (IDENTITY_2,), True),
    # not specifying the exact encryption identities leads to an error: the ring misses IDENTITY_3
    (IDENTITY_1, (IDENTITY_2, IDENTITY_3), (), False),
    (IDENTITY_1, (IDENTITY_2, IDENTITY_3), (IDENTITY_1, IDENTITY_2), True),
], ids=["implicit", "explicit", "missing-recipient-implicit", "missing-recipient-explicit"])
def test_arbitrary_encrypt_cli(cli, make_ring, from_, to, encrypt, valid):
    ring = make_ring((KEY_2, GPG_PASSPHRASE), KEY_1)  # the ring has both identities
    output = cli("--from", from_, "--to", *to, "--encrypt", *encrypt, stdin=MESSAGE, env={"GNUPGHOME": ring})
    assert (PGP_MESSAGE if valid else "Signing/encrypting failed.") in output


@pytest.mark.cli
def test_arbitrary_encrypt_cli_empty_ring_and_key_import(cli, make_ring):
    ring = make_ring()
    key1_armored = (GPG_KEYS / KEY_1).read_text()

    def run(from_, to, encrypt, valid=True):
        output = cli("--from", from_, "--to", *to, "--encrypt", *encrypt, stdin=MESSAGE, env={"GNUPGHOME": ring})
        assert (PGP_MESSAGE if valid else "Signing/encrypting failed.") in output

    run(IDENTITY_1, (IDENTITY_2,), (), False)  # the ring has none
    run(IDENTITY_1, (IDENTITY_2, IDENTITY_3), (key1_armored,))  # insert IDENTITY_1 into the ring
    run(IDENTITY_2, (IDENTITY_1,), (), False)  # IDENTITY_2 still misses in the ring
    run(IDENTITY_2, (IDENTITY_1,), ("--no-from",))  # --no-from suppresses the need for IDENTITY_2


@pytest.fixture
def signing_model(home):
    return Envelope(MESSAGE).to(f"{IDENTITY_3}, {IDENTITY_1}").from_(IDENTITY_2).gpg(home)


@pytest.mark.parametrize(("signature", "encryption", "warning"), [
    (False, [IDENTITY_3, "invalid"],
     f"Key for {IDENTITY_3}, invalid seems missing, see: GNUPGHOME={{home}} gpg --list-keys"),
    (False, [IDENTITY_1], None),
    (IDENTITY_1, [IDENTITY_1], None),
    (IDENTITY_3, [IDENTITY_1],
     f"The secret key for {IDENTITY_3} seems to not be used,"
     " check if it is in the keyring: GNUPGHOME={home} gpg --list-secret-keys"),
    (IDENTITY_3, False,
     f"The secret key for {IDENTITY_3} seems to not be used,"
     " check if it is in the keyring: GNUPGHOME={home} gpg --list-secret-keys"),
], ids=["unknown-encryption-key", "encrypt-only", "sign-and-encrypt", "unknown-signing-key-encrypt",
        "unknown-signing-key"])
def test_arbitrary_encrypt_with_signing(signing_model, home, caplog, signature, encryption, warning):
    e = signing_model.copy().signature(signature).encryption(encryption)
    if warning:
        with caplog.at_level(logging.WARNING, logger="envelope"):
            assert str(e) == ""
        assert_warned(caplog, warning.format(home=home))
    else:
        assert PGP_MESSAGE in str(e)


def test_encrypt_signed_with_unknown_key_fails(signing_model):
    assert str(signing_model.copy().encrypt(IDENTITY_2, sign=IDENTITY_3)) == ""


def test_encrypt_signed_with_known_key(signing_model):
    assert PGP_MESSAGE in str(signing_model.copy().encrypt(IDENTITY_2, sign=IDENTITY_1))


# ---------------------------------------------------------------- key auto-import

def test_auto_import_empty_ring_cannot_sign(empty_gpg_home_factory):
    e = Envelope(MESSAGE).gpg(str(empty_gpg_home_factory())).signature()
    with pytest.raises(RuntimeError):
        str(e)


def test_auto_import_key_stays_in_ring(empty_gpg_home_factory):
    ring = str(empty_gpg_home_factory())
    # import key to the ring
    assert_lines(Envelope(MESSAGE).gpg(ring).sign(GPG_KEYS / KEY_1),
                 MESSAGE, SIGNATURE_BEGIN, SIGNATURE_END, min_lines=10)
    # key in the ring from last time
    assert_lines(Envelope(MESSAGE).gpg(ring).signature(), MESSAGE, SIGNATURE_BEGIN, SIGNATURE_END, min_lines=10)


def test_auto_import_identity_2_missing(make_ring):
    ring = make_ring(KEY_1)

    # cannot encrypt for identity-2
    assert produced(Envelope(MESSAGE).gpg(ring).from_(IDENTITY_1).to(IDENTITY_2).encryption()) is False

    # signing should fail since we have not imported key for identity-2
    with pytest.raises(RuntimeError):
        str(Envelope(MESSAGE).gpg(ring).from_(IDENTITY_2).signature())

    # however it should pass when we explicitly use an existing GPG key to be signed with
    e = Envelope(MESSAGE).gpg(ring).from_(IDENTITY_2).signature(IDENTITY_1_GPG_FINGERPRINT)
    assert_lines(e, MESSAGE, SIGNATURE_BEGIN, SIGNATURE_END, min_lines=10)
    assert bool(e) is True


def test_auto_import_encryption_key_and_passphrase(make_ring):
    ring = make_ring(KEY_1)

    # import encryption key - no passphrase needed while importing or using public key
    e = Envelope(MESSAGE).gpg(ring).from_(IDENTITY_1).to(IDENTITY_2).encryption(GPG_KEYS / KEY_2)
    assert produced(e) is True

    # signing with an invalid passphrase should fail for identity-2
    assert produced(Envelope(MESSAGE).gpg(ring).from_(IDENTITY_2).signature(passphrase="INVALID PASSPHRASE")) is False

    # signing with a valid passphrase should pass
    assert produced(Envelope(MESSAGE).gpg(ring).from_(IDENTITY_2).signature(passphrase=GPG_PASSPHRASE)) is True


# ---------------------------------------------------------------- loading GPG messages

def test_load_signed_gpg():
    # XX we should test signature verification with e._gpg_verify(),
    # however .load does not load application/pgp-signature content at the moment
    assert Envelope.load(path=EML_DIR / "test_signed_gpg.eml").message() == MESSAGE


@pytest.mark.parametrize(("filename", "expected"), [
    ("test_encrypted_gpg.eml", "dumb encrypted message"),
    ("test_encrypted_signed_gpg.eml", "dumb encrypted and signed message"),
], ids=["encrypted", "encrypted-signed"])
def test_load_encrypted_gpg(filename, expected):
    assert Envelope.load(path=EML_DIR / filename).message() == expected


# ---------------------------------------------------------------- encrypted subject

ENCRYPTED_SUBJECT = "Encrypted message"
SUBJECT = "This is an encrypted subject"
BODY = "just a body text"


@pytest.fixture
def subject_ref(home):
    return Envelope(BODY).gpg(home).to(IDENTITY_2).from_(IDENTITY_1).encryption()


def test_encrypted_gpg_subject_is_hidden_and_decrypted_on_load(subject_ref):
    encrypted_eml = subject_ref.subject(SUBJECT).as_message().as_string()

    # subject has been encrypted
    assert "Subject: " + ENCRYPTED_SUBJECT in encrypted_eml
    assert SUBJECT not in encrypted_eml

    # subject has been decrypted
    e = Envelope.load(encrypted_eml)
    assert e.message() == BODY
    assert e.subject() == SUBJECT


@pytest.mark.parametrize(("subject_args", "placeholder"), [
    ((SUBJECT, True), ENCRYPTED_SUBJECT),  # the default behaviour
    ((SUBJECT, "Front text"), "Front text"),  # choose another placeholder text
], ids=["default-placeholder", "custom-placeholder"])
def test_encrypted_gpg_subject_placeholder(subject_ref, subject_args, placeholder):
    encrypted = subject_ref.subject(*subject_args).as_message().as_string()
    assert placeholder in encrypted
    assert SUBJECT not in encrypted

    decrypted = Envelope.load(encrypted).as_message().as_string()
    assert SUBJECT in decrypted
    assert placeholder not in decrypted


def test_encrypted_gpg_subject_can_stay_visible(subject_ref):
    always_visible = subject_ref.subject(SUBJECT, encrypted=False).as_message().as_string()  # do not encrypt
    assert SUBJECT in always_visible
    assert SUBJECT in Envelope.load(always_visible).as_message().as_string()


# ---------------------------------------------------------------- long attachment filename

# Message.as_string() unfolds the long `Content-Disposition` header while Message.get_payload()[0].as_string()
# folds it, which breaks a GPG signature of attachments with file names longer than 34 chars. Envelope corrects
# this when sending or outputting, but not via Envelope.as_message(). See #19 and
# https://github.com/python/cpython/issues/99533

@pytest.fixture
def signed_attachment(home):
    return (Envelope(MESSAGE).to(IDENTITY_2).gpg(home).from_(IDENTITY_1)
            .signature(IDENTITY_2_FINGERPRINT, GPG_PASSPHRASE)
            .attach("some data", name="A" * 35))


def verify_inline_message(e: Envelope, txt: str) -> bool:
    boundary = re.search(r'boundary="(.*)"', txt).group(1)
    reg = fr'{boundary}.*{boundary}\n(.*)\n--{boundary}.*(-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----)'
    m = re.search(reg, txt, re.DOTALL)
    return e._gpg_verify(m[2].encode(), m[1].encode())


def test_long_attachment_filename_payload_parts_keep_signature(signed_attachment):
    # accessing via standard email package with get_payload called on different parts keeps signature
    e = signed_attachment
    sig = e.as_message().get_payload()[1].get_payload().encode()
    data = e.as_message().get_payload()[0].as_bytes()
    assert e._gpg_verify(sig, data)


def test_long_attachment_filename_as_message_breaks_signature(signed_attachment):
    # When this test fails it means the Python package was corrected. Good news! Let's get rid of #19 mocking.
    assert not verify_inline_message(signed_attachment, signed_attachment.as_message().as_string())


@pytest.mark.parametrize("render", [lambda e: bytes(e).decode(), str], ids=["bytes", "str"])
def test_long_attachment_filename_corrected_on_output(signed_attachment, render):
    assert verify_inline_message(signed_attachment, render(signed_attachment))


def test_long_attachment_filename_corrected_on_send(signed_attachment, monkeypatch):
    verified = []

    def check_sending(self, email, **_):
        verified.append(verify_inline_message(signed_attachment, signed_attachment.as_message().as_string()))

    monkeypatch.setattr(SMTPHandler, "send_message", check_sending)
    signed_attachment.send()
    assert verified == [True]
