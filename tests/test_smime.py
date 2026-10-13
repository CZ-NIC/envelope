""" S/MIME signing, encryption and decryption.

How the fixtures in tests/fixtures/smime and tests/fixtures/smime_chained were generated:

Simple (not chained) key and its certificate, valid for 100 years:
    openssl req -newkey rsa:1024 -nodes -x509 -days 36500 -out certificate.pem

Chained certificates:
    # root CA
    openssl genrsa -out rootCA.key 2048
    openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 36500 -out rootCA.crt -subj "/CN=Dummy Root CA"

    # intermediate CA with proper CA extensions
    openssl genrsa -out intermediateCA.key 2048
    openssl req -new -key intermediateCA.key -out intermediateCA.csr -subj "/CN=Dummy Intermediate CA"
    openssl x509 -req -in intermediateCA.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
        -out intermediateCA.crt -days 36500 -sha256 \
        -extensions v3_ca -extfile <(echo "[v3_ca]"; echo "basicConstraints=CA:TRUE"; echo "keyUsage=keyCertSign,cRLSign")

    # signer certificate with email protection extensions
    openssl genrsa -out signer.key 2048
    openssl req -new -key signer.key -out signer.csr -subj "/CN=Dummy SMIME Signer"
    openssl x509 -req -in signer.csr -CA intermediateCA.crt -CAkey intermediateCA.key -CAcreateserial \
        -out signer.crt -days 36500 -sha256 \
        -extensions email_ext -extfile <(echo "[email_ext]"; echo "keyUsage=digitalSignature,keyEncipherment"; echo "extendedKeyUsage=emailProtection")

    # signer certificate with a passphrase ("test") and email protection extensions
    openssl genpkey -algorithm RSA -aes256 -pkeyopt rsa_keygen_bits:2048 -pass pass:test -out signer_passphrase.key
    openssl req -new -key signer_passphrase.key -passin pass:test -out signer_passphrase.csr -subj "/CN=Dummy SMIME Signer"
    openssl x509 -req -in signer_passphrase.csr -CA intermediateCA.crt -CAkey intermediateCA.key -CAcreateserial \
        -out signer_passphrase.crt -days 36500 -sha256 \
        -extensions email_ext -extfile <(echo "[email_ext]"; echo "keyUsage=digitalSignature,keyEncipherment"; echo "extendedKeyUsage=emailProtection")

    # chained certificate files
    cat signer.crt intermediateCA.crt > chained_cert.pem
    cat signer.key chained_cert.pem > key-chained-cert-together.pem
    cat signer_passphrase.key signer_passphrase.crt intermediateCA.crt > key-chained-cert-together-passphrase.pem
"""
import os
import re
import sys
from base64 import b64decode, b64encode

import pytest

pytest.importorskip("cryptography")

from envelope import Envelope  # noqa: E402
from envelope.parser import Parser  # noqa: E402
from helpers import (EML_DIR, GPG_KEYS, GPG_PASSPHRASE, IDENTITY_2, IMAGE_FILE, MESSAGE, SMIME_CHAINED_DIR,  # noqa: E402
                     SMIME_DIR, TEXT_ATTACHMENT, assert_lines, run_subprocess)

pytestmark = pytest.mark.smime

SMIME_KEY = SMIME_DIR / "key.pem"
SMIME_CERT = SMIME_DIR / "cert.pem"
KEY_CERT_TOGETHER = SMIME_DIR / "key-cert-together.pem"
KEY_CERT_TOGETHER_PASSPHRASE = SMIME_DIR / "key-cert-together-passphrase.pem"
IDENTITY_KEY = SMIME_DIR / "smime-identity@example.com-key.pem"
IDENTITY_CERT = SMIME_DIR / "smime-identity@example.com-cert.pem"

CHAINED_SIGNER_KEY = SMIME_CHAINED_DIR / "signer.key"
CHAINED_SIGNER_CERT = SMIME_CHAINED_DIR / "signer.crt"
CHAINED_CERT = SMIME_CHAINED_DIR / "chained_cert.pem"
CHAINED_KEY_CERT_TOGETHER = SMIME_CHAINED_DIR / "key-chained-cert-together.pem"
CHAINED_KEY_CERT_TOGETHER_PASSPHRASE = SMIME_CHAINED_DIR / "key-chained-cert-together-passphrase.pem"
CHAINED_ROOT_CERT = SMIME_CHAINED_DIR / "rootCA.crt"

SIGNATURE_DISPOSITION = 'Content-Disposition: attachment; filename="smime.p7s"'
SIGNATURE_START = "MIIEUwYJKoZIhvcNAQcCoIIERDCCBEACAQExDzANBglghkgBZQMEAgEFADALBgkq"
CHAINED_SIGNATURE_START = "MIIIoQYJKoZIhvcNAQcCoIIIkjCCCI4CAQExDzANBglghkgBZQMEAgEFADALBgkq"
ENCRYPTED_CONTENT_TYPE = 'Content-Type: application/pkcs7-mime; smime-type="enveloped-data"; name="smime.p7m"'
ENCRYPTED_LINE = "Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF"
VERIFIED = "CMS Verification successful"


def openssl_verify(signed_message: Envelope, root_ca: os.PathLike, tmp_path) -> str:
    """ Verify the S/MIME signature using OpenSSL and the root CA certificate.
    The message has to be signed by the signer and the intermediate CA. Return the openssl output. """
    signed_file = tmp_path / "signed_message.eml"
    signed_file.write_text(signed_message.as_message().as_string())
    return run_subprocess("openssl", "cms", "-verify", "-in", signed_file, "-CAfile", root_ca, "-out", os.devnull)


def decrypt(key, cert, envelope):
    """ Decrypt the envelope; return False if the key is not among its recipients. """
    return Parser(key=str(key), cert=str(cert)).smime_decrypt(envelope)


def test_sign():
    assert_lines(Envelope(MESSAGE)
                 .smime()
                 .subject("my subject")
                 .reply_to("test-reply@example.com")
                 .signature(SMIME_KEY, cert=SMIME_CERT)
                 .send(False),
                 "Subject: my subject", "Reply-To: test-reply@example.com", MESSAGE,
                 SIGNATURE_DISPOSITION, SIGNATURE_START, min_lines=10)


def test_sign_key_cert_together():
    assert_lines(Envelope(MESSAGE).smime().signature(KEY_CERT_TOGETHER).sign(),
                 SIGNATURE_DISPOSITION, SIGNATURE_START)


def test_sign_key_cert_together_passphrase():
    assert_lines(Envelope(MESSAGE).smime().signature(KEY_CERT_TOGETHER_PASSPHRASE, passphrase=GPG_PASSPHRASE).sign(),
                 SIGNATURE_DISPOSITION, SIGNATURE_START, min_lines=10)


def test_sign_passphrase_rendered_twice():
    """ The passphrase used to be encoded in place, so the second render crashed. """
    e = Envelope(MESSAGE).smime().subject("a").signature(KEY_CERT_TOGETHER_PASSPHRASE, passphrase=GPG_PASSPHRASE)
    str(e)
    e.subject("b")
    assert "Subject: b" in str(e)


def test_chained_sign(tmp_path):
    signed = (Envelope(MESSAGE)
              .smime()
              .subject("my subject")
              .reply_to("test-reply@example.com")
              .signature(CHAINED_SIGNER_KEY, cert=CHAINED_CERT)
              .send(False))
    assert_lines(signed, "Subject: my subject", "Reply-To: test-reply@example.com", MESSAGE,
                 SIGNATURE_DISPOSITION, CHAINED_SIGNATURE_START,
                 min_lines=10)
    assert openssl_verify(signed, CHAINED_ROOT_CERT, tmp_path) == VERIFIED


def test_chained_sign_without_intermediate_fails_verification(tmp_path):
    signed = (Envelope(MESSAGE)
              .smime()
              .subject("my subject")
              .reply_to("test-reply@example.com")
              .signature(CHAINED_SIGNER_KEY, cert=CHAINED_SIGNER_CERT)
              .send(False))
    assert_lines(signed, "Subject: my subject", "Reply-To: test-reply@example.com", MESSAGE,
                 SIGNATURE_DISPOSITION, "MIIFeAYJKoZIhvcNAQcCoIIFaTCCBWUCAQExDzANBglghkgBZQMEAgEFADALBgkq",
                 min_lines=10)
    assert openssl_verify(signed, CHAINED_ROOT_CERT, tmp_path) != VERIFIED


def test_chained_sign_key_cert_together(tmp_path):
    signed = (Envelope(MESSAGE)
              .smime()
              .subject("my subject")
              .reply_to("test-reply@example.com")
              .signature(CHAINED_KEY_CERT_TOGETHER)
              .send(False))
    assert_lines(signed, SIGNATURE_DISPOSITION, CHAINED_SIGNATURE_START)
    assert openssl_verify(signed, CHAINED_ROOT_CERT, tmp_path) == VERIFIED


def test_chained_sign_key_cert_together_passphrase(tmp_path):
    signed = (Envelope(MESSAGE)
              .smime()
              .subject("my subject")
              .reply_to("test-reply@example.com")
              .signature(CHAINED_KEY_CERT_TOGETHER_PASSPHRASE, passphrase=GPG_PASSPHRASE)
              .send(False))
    assert_lines(signed, SIGNATURE_DISPOSITION, CHAINED_SIGNATURE_START, min_lines=10)
    assert openssl_verify(signed, CHAINED_ROOT_CERT, tmp_path) == VERIFIED


def test_encrypt():
    assert_lines(Envelope(MESSAGE)
                 .smime()
                 .reply_to("test-reply@example.com")
                 .subject("my message")
                 .encryption(SMIME_CERT)
                 .send(False),
                 ENCRYPTED_CONTENT_TYPE, "Subject: my message", "Reply-To: test-reply@example.com", ENCRYPTED_LINE,
                 min_lines=10)


def test_detection_implicit_gpg():
    """ We do not explicitly tell that we are using GPG or S/MIME. """
    gpg_key = GPG_KEYS / f"{IDENTITY_2}.key"
    encrypting = Envelope(MESSAGE).from_(IDENTITY_2).to(IDENTITY_2).encryption(key=gpg_key)
    assert_lines(encrypting)
    assert bool(encrypting) is True

    signing = Envelope(MESSAGE).from_(IDENTITY_2).to(IDENTITY_2).signature(key=gpg_key, passphrase=GPG_PASSPHRASE)
    assert_lines(signing)
    assert bool(signing) is True


def test_detection_implicit_smime_sign():
    assert_lines(Envelope(MESSAGE)
                 .subject("my subject")
                 .reply_to("test-reply@example.com")
                 .signature(KEY_CERT_TOGETHER)
                 .send(False),
                 "Subject: my subject", "Reply-To: test-reply@example.com", MESSAGE,
                 SIGNATURE_DISPOSITION, SIGNATURE_START, min_lines=10)


def test_detection_implicit_smime_encrypt():
    assert_lines(Envelope(MESSAGE)
                 .subject("my subject")
                 .reply_to("test-reply@example.com")
                 .encryption(KEY_CERT_TOGETHER)
                 .send(False),
                 ENCRYPTED_CONTENT_TYPE, "Subject: my subject", "Reply-To: test-reply@example.com", ENCRYPTED_LINE,
                 min_lines=10)


@pytest.mark.parametrize("ciphering", [{"sign": SMIME_KEY, "cert": SMIME_CERT},
                                       {"sign": KEY_CERT_TOGETHER_PASSPHRASE, "passphrase": GPG_PASSPHRASE},
                                       {"encrypt": SMIME_CERT}])
def test_detection_implicit_smime_without_m2crypto(monkeypatch, ciphering):
    """ S/MIME is detected with the `smime` extra only (M2Crypto used to be needed, otherwise GPG was tried). """
    monkeypatch.setitem(sys.modules, "M2Crypto", None)
    e = Envelope(MESSAGE, **ciphering).send(False)
    assert bool(e) is True
    assert ("smime.p7m" if "encrypt" in ciphering else "smime.p7s") in str(e)


def test_detection_implicit_smime_without_cryptography(monkeypatch):
    """ Without the `smime` extra, a certificate must not be passed to GPG. """
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.serialization", None)
    with pytest.raises(ImportError, match="smime"):
        Envelope(MESSAGE).encryption(SMIME_CERT).send(False)


def test_multiple_recipients():
    # encrypt for both keys
    output = (Envelope(MESSAGE)
              .smime()
              .reply_to("test-reply@example.com")
              .subject("my message")
              .encrypt([SMIME_CERT, IDENTITY_CERT]))
    for key, cert in ((IDENTITY_KEY, IDENTITY_CERT), (SMIME_KEY, SMIME_CERT)):
        decrypted = decrypt(key, cert, output)
        assert decrypted, f"{cert.name} cannot decrypt the message"
        assert re.search(MESSAGE, decrypted.decode("utf-8"))

    # encrypt for a single key only
    output = (Envelope(MESSAGE)
              .smime()
              .reply_to("test-reply@example.com")
              .subject("my message")
              .encrypt([SMIME_CERT]))
    assert not decrypt(IDENTITY_KEY, IDENTITY_CERT, output)
    assert re.search(MESSAGE, decrypt(SMIME_KEY, SMIME_CERT, output).decode("utf-8"))


def test_encrypt_with_cert():
    """ Encrypted both for the recipients and for the sender's cert (that used to override the recipients). """
    output = Envelope(MESSAGE, cert=SMIME_CERT).smime().subject("my message").encrypt([IDENTITY_CERT])
    for key, cert in ((IDENTITY_KEY, IDENTITY_CERT), (SMIME_KEY, SMIME_CERT)):
        decrypted = decrypt(key, cert, output)
        assert decrypted, f"{cert.name} cannot decrypt the message"
        assert re.search(MESSAGE, decrypted.decode("utf-8"))

    # without explicit recipients, encrypted for the cert only
    output = Envelope(MESSAGE, cert=SMIME_CERT).smime().subject("my message").encrypt()
    assert not decrypt(IDENTITY_KEY, IDENTITY_CERT, output)
    assert re.search(MESSAGE, decrypt(SMIME_KEY, SMIME_CERT, output).decode("utf-8"))


@pytest.mark.parametrize("signer", [
    {"key": KEY_CERT_TOGETHER},  # used to crash: the certificate was not taken from the key file
    {"key": SMIME_KEY, "cert": SMIME_CERT},
])
def test_sign_encrypt(signer):
    """ Signed and encrypted both for the recipient and for the sender. """
    output = (Envelope(MESSAGE)
              .smime()
              .subject("my message")
              .signature(**signer)
              .encrypt([IDENTITY_CERT]))
    for key, cert in ((IDENTITY_KEY, IDENTITY_CERT), (SMIME_KEY, SMIME_CERT)):
        decrypted = decrypt(key, cert, output)
        assert decrypted, f"{cert.name} cannot decrypt the message"
        assert re.search(MESSAGE, decrypted.decode("utf-8"))
        assert b'Content-Disposition: attachment; filename="smime.p7s"' in decrypted


def test_sign_encrypt_invalid_key():
    with pytest.raises(ValueError, match="Error loading private key"):
        Envelope(MESSAGE).smime().signature(IDENTITY_CERT).encrypt([IDENTITY_CERT])


def test_decrypt():
    """ The fixture was encrypted by `openssl smime -encrypt -aes256`. """
    e = Envelope.load(path=str(EML_DIR / "smime_encrypt_aes.eml"), key=str(SMIME_KEY), cert=str(SMIME_CERT))
    assert e.message() == MESSAGE
    assert e.subject() == "my message"


def test_decrypt_legacy_3des(caplog):
    """ pyca cryptography decrypts AES-CBC only; legacy 3DES is reported (M2Crypto used to decrypt it). """
    e = Envelope.load(path=str(EML_DIR / "smime_encrypt.eml"), key=str(SMIME_KEY), cert=str(SMIME_CERT))
    assert "Cannot decrypt S/MIME" in caplog.text
    assert e.message() != MESSAGE


def test_decrypt_attachments():
    body = "an encrypted message with the attachments"  # note that the inline image is not referenced in the text
    encrypted = (Envelope(body)
                 .smime()
                 .reply_to("test-reply@example.com")
                 .subject("my message")
                 .encryption(SMIME_CERT)
                 .attach(path=str(TEXT_ATTACHMENT))
                 .attach(IMAGE_FILE, inline=True)
                 .as_message().as_string())

    decrypted = decrypt(SMIME_KEY, SMIME_CERT, encrypted.encode("utf-8")).decode("utf-8")

    assert re.search(body, decrypted), decrypted

    # number of attachments, of which inline
    assert len(re.findall(r"Content-Disposition: (attachment|inline)", decrypted)) == 2
    assert len(re.findall(r"Content-Disposition: inline", decrypted)) == 1

    # the inline attachment: only the gif data
    marker = "Content-Disposition: inline"
    inline_data = decrypted[decrypted.index(marker) + len(marker):].strip().replace("\n", "").replace("\r", "")
    inline_data = inline_data[:inline_data.index("==") + 2]
    assert inline_data == b64encode(IMAGE_FILE.read_bytes()).decode("ascii")

    # the generic.txt attachment
    marker = 'Content-Disposition: attachment; filename="generic.txt"'
    encoded = decrypted[decrypted.index(marker):].split("\n\n")[1].strip() + "=="
    assert b64decode(encoded).decode("utf-8") == TEXT_ATTACHMENT.read_text()


# XX smime_sign.eml is not used right now. Make signature verification possible first.
# def test_load_signed():
#     e = Envelope.load(path="tests/fixtures/eml/smime_sign.eml", key=SMIME_KEY, cert=SMIME_CERT)
#     assert e.message() == MESSAGE


def test_load_key_cert_together():
    # XX verify signature
    e = Envelope.load(path=str(EML_DIR / "smime_key_cert_together.eml"), key=KEY_CERT_TOGETHER)
    assert e.message() == MESSAGE
