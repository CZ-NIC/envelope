import logging
import re
import sys
from base64 import b64encode
from contextlib import redirect_stdout
from email.message import EmailMessage
from io import StringIO
from os import environ
from pathlib import Path
from subprocess import PIPE, STDOUT, Popen
from tempfile import TemporaryDirectory
from typing import Tuple, Union
from unittest import main, TestCase, mock

from envelope import Envelope
from envelope.address import Address, _parseaddr, _getaddresses
from envelope.constants import AUTO, PLAIN, HTML
from envelope.parser import Parser
from envelope.smtp_handler import SMTPHandler
from envelope.utils import assure_list, assure_fetched, get_mimetype

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

GPG_PASSPHRASE = "test"
IDENTITY_1_GPG_FINGERPRINT = "F14F2E8097E0CCDE93C4E871F4A4F26779FA03BB"
IDENTITY_1 = "envelope-example-identity@example.com"
IDENTITY_2 = "envelope-example-identity-2@example.com"
IDENTITY_3 = "envelope-example-identity-3@example.com"
GNUPG_HOME = "tests/gpg_ring/"
PGP_MESSAGE = "-----BEGIN PGP MESSAGE-----"
MESSAGE = "dumb message"
environ["GNUPGHOME"] = GNUPG_HOME


class TestAbstract(TestCase):
    utf_header = Path("tests/eml/utf-header.eml")  # the file has encoded headers
    charset = Path("tests/eml/charset.eml")  # the file has encoded headers
    internationalized = Path("tests/eml/internationalized.eml")
    quopri = Path("tests/eml/quopri.eml")  # the file has CRLF separators
    eml = Path("tests/eml/mail.eml")
    text_attachment = "tests/eml/generic.txt"
    image_file = Path("tests/eml/image.gif")
    group_recipient = Path("tests/eml/group-recipient.eml")
    invalid_characters = Path("tests/eml/invalid-characters.eml")
    invalid_headers = Path("tests/eml/invalid-headers.eml")

    def check_lines(self, o, lines: Union[str, Tuple[str, ...]] = (), longer: Union[int, Tuple[int, int]] = None,
                    debug=False, not_in: Union[str, Tuple[str, ...]] = (), raises=(), result=None):
        """ Converts Envelope objects to str and asserts that lines are present.
        :type lines: Assert in. These line/s must be found in the given order.
        :type not_in: Assert not in.
        :type longer: If int → result must be longer than int. If tuple → result line count must be within tuple range.
        """
        if type(lines) is str:
            lines = lines,
        if type(not_in) is str:
            not_in = not_in,

        if raises:
            self.assertRaises(raises, str, o)
            output = None
        else:
            output = str(o).splitlines()

            # any line is not longer than 1000 characters
            self.assertFalse(any(line for line in output if len(line) > 999))

        if debug:
            print(o)
        output_tmp = output
        last_search = ""
        for search in lines:
            try:
                index = output_tmp.index(search)
            except ValueError:
                message = f"is in the wrong order (above the line '{last_search}' )" \
                    if search in output else "not found"
                self.fail(f"Line '{search}' {message} in the output:\n{o}")
            output_tmp = output_tmp[index + 1:]
            last_search = search
        for search in not_in:
            self.assertNotIn(search, output)

        # result state
        if result is not None:
            self.assertIs(bool(o), result)

        # result line count range
        if type(longer) is tuple:
            longer, shorter = longer
            self.assertLess(len(output), shorter)
        if longer:
            self.assertGreater(len(output), longer)

    cmd = "python3", "-m", "envelope"

    def bash(self, *cmd, file: Path = None, piped=None, envelope=True, env=None, debug=False, decode=True):
        """

        :param cmd: Any number of commands.
        :param file: File piped to the program.
        :param piped: Content piped to the program.
        :param envelope: Prepend envelope module call before commands.
        :param env: dict Modify environment variables.
        :param debug: Print debug info.
        :param decode: Decode the output by default.
        :return:
        """
        if envelope:
            cmd = self.cmd + cmd
        if not file and not piped:
            file = self.eml

        if debug:
            print("Cmd:")
            r = [f"{' '.join(cmd)}"]
            if file:
                r.append(f" < {file}")
            elif piped:
                r = [f'echo "{piped}" |'] + r
            print(" ".join(r))

        if env:
            env = {**environ.copy(), **env}

        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=STDOUT, env=env)
        r = p.communicate(input=file.read_bytes() if file else piped.encode("utf-8"))[0]
        if decode:
            return r.decode().rstrip()
        else:
            return r

    def assertSubset(self, dict_, subset):
        """ assertDictContainsSubset alternative """
        self.assertEqual(dict_, {**dict_, **subset})  # XX make (dict_, dict_ | subset) as of Python3.9


class TestInternal(TestCase):

    def test_assure_list(self):
        t = ["one", "two"]
        self.assertEqual([], assure_list(None))
        self.assertEqual(["test"], assure_list("test"))
        self.assertEqual([5], assure_list(5))
        self.assertEqual([False], assure_list(False))
        self.assertEqual([b"test"], assure_list(b"test"))
        self.assertEqual([0, 1, 2], assure_list(x for x in range(3)))
        self.assertEqual([0, 1, 2], assure_list([x for x in range(3)]))
        self.assertCountEqual([0, 1, 2], assure_list({x for x in range(3)}))
        self.assertEqual([0, 1, 2], assure_list({x: "nothing" for x in range(3)}))
        self.assertEqual([0, 1, 2], assure_list({x: "nothing" for x in range(3)}.keys()))
        self.assertEqual(t, assure_list(tuple(t)))
        self.assertCountEqual(t, assure_list(frozenset(t)))

    def test_assure_fetched(self):
        self.assertEqual(b"test", assure_fetched("test", bytes))
        self.assertEqual("test", assure_fetched("test", str))
        self.assertEqual(False, assure_fetched(False, str))
        self.assertEqual(None, assure_fetched(None, str))
        self.assertEqual(b"test", assure_fetched(b"test", bytes))
        self.assertEqual("test", assure_fetched(b"test", str))
        self.assertEqual("test", assure_fetched(b"test", str))
        self.assertEqual("test", assure_fetched(StringIO("test"), str))
        self.assertEqual(b"test", assure_fetched(StringIO("test"), bytes))


class TestEnvelope(TestAbstract):
    def test_message_generating(self):
        self.check_lines(Envelope(MESSAGE)
                         .subject("my subject")
                         .send(False),
                         ("Subject: my subject",
                          MESSAGE,), 10)

    def test_1000_split(self):
        self.check_lines(Envelope().message("short text").subject("my subject").send(False),
                         ('Content-Type: text/plain; charset="utf-8"',
                          'Content-Transfer-Encoding: 7bit',
                          "Subject: my subject",
                          "short text"), 10)

        # this should be no more 7bit but base64 (or quoted-printable which is however not guaranteed)
        e = Envelope().message("Longer than thousand chars. " * 1000).subject("my subject").send(False)
        self.check_lines(e,
                         ('Content-Type: text/plain; charset="utf-8"',
                          "Content-Transfer-Encoding: base64",
                          "Subject: my subject",), 100,
                         not_in=('Content-Transfer-Encoding: 7bit',)
                         )
        self.assertFalse(any(line for line in str(e).splitlines() if len(line) > 999))

    def test_1000_split_html(self):
        # the same is valid for HTML alternative too
        e = (Envelope()
             .message("short text")
             .message("<b>html</b>", alternative="html")
             .subject("my subject"))

        # 7bit both plain and html
        self.check_lines(e.send(False),
                         ("Subject: my subject",
                          'Content-Type: text/plain; charset="utf-8"',
                          'Content-Transfer-Encoding: 7bit',
                          "short text",
                          'Content-Type: text/html; charset="utf-8"',
                          'Content-Transfer-Encoding: 7bit',
                          "<b>html</b>"), 10)

        # 7bit html, base64 plain
        self.check_lines(e.copy().message("Longer than thousand chars. " * 1000).send(False),
                         ("Subject: my subject",
                          'Content-Type: text/plain; charset="utf-8"',
                          "Content-Transfer-Encoding: base64",
                          'Content-Type: text/html; charset="utf-8"',
                          'Content-Transfer-Encoding: 7bit',
                          "<b>html</b>"
                          ), 100,
                         not_in=('short text')
                         )

        # 7bit plain, base64 html
        self.check_lines(e.copy().message("Longer than thousand chars. " * 1000, alternative="html").send(False),
                         ("Subject: my subject",
                          'Content-Type: text/plain; charset="utf-8"',
                          'Content-Transfer-Encoding: 7bit',
                          'short text',
                          'Content-Type: text/html; charset="utf-8"',
                          "Content-Transfer-Encoding: base64",
                          ), 100,
                         not_in="<b>html</b>"
                         )

        # base64 both plain and html
        self.check_lines(e.copy().message("Longer than thousand chars. " * 1000, alternative="html")
                         .message("Longer than thousand chars. " * 1000).send(False),
                         ("Subject: my subject",
                          'Content-Type: text/plain; charset="utf-8"',
                          "Content-Transfer-Encoding: base64",
                          'Content-Type: text/html; charset="utf-8"',
                          "Content-Transfer-Encoding: base64",
                          ), 100,
                         not_in=('Content-Transfer-Encoding: 7bit',
                                 'short text',
                                 "<b>html</b>")
                         )

    def test_missing_message(self):
        self.assertEqual(Envelope().to("hello").preview(), "")

    def test_contents_fetching(self):
        t = "Small sample text attachment.\n"
        with open("tests/eml/generic.txt") as f:
            e1 = Envelope(f)
            e2 = e1.copy()  # stays intact even if copied to another instance
            self.assertEqual(e1.message(), t)
            self.assertEqual(e2.message(), t)
        self.assertEqual(e2.copy().message(), t)

    def test_preview(self):
        self.check_lines(Envelope(Path("tests/eml/generic.txt")).preview(),
                         ('Content-Type: text/plain; charset="utf-8"',
                          "Subject: ",
                          "Small sample text attachment."))

    def test_equality(self):
        source = {"message": "message", "subject": "hello"}
        e1 = Envelope(**source).date(False)
        e2 = Envelope(**source).date(False)
        self.assertEqual(e1, e2)
        self.assertEqual(str(e1), e2)
        self.assertEqual(bytes(e1), e2)

        s = 'Content-Type: text/plain; charset="utf-8"\nContent-Transfer-Encoding: 7bit' \
            '\nMIME-Version: 1.0\nSubject: hello\n\nmessage\n'
        b = bytes(s, "utf-8")
        self.assertEqual(s, e1)
        self.assertEqual(s, str(e1))
        self.assertEqual(b, e1)
        self.assertEqual(b, bytes(e1))

    def test_bcc_ignored(self):
        e = Envelope(**{"message": "message", "subject": "hello", "cc": "person-cc@example.com",
                        "bcc": "person-bcc@example.com"})
        self.assertIn("person-bcc@example.com", e.recipients())
        self.check_lines(e, ('Cc: person-cc@example.com',), not_in=('Bcc: person-bcc@example.com',))

    def test_internal_cache(self):
        e = Envelope("message").date(False)  # Date might interfere with the Envelope objects equality
        e.header("header1", "1")

        # create cache under the hood
        self.assertFalse(e._result)
        # noinspection PyStatementEffect
        e.as_message()["header1"]
        self.assertTrue(e._result)

        # as soon as object changed, cache regenerated
        e.header("header2", "1")
        e2 = Envelope("message").header("header1", "1").header("header2", "1").date(False)
        self.assertEqual("1", e.as_message()["header2"])
        self.assertEqual(e2, e)
        self.check_lines(e, "header2: 1")

    def test_wrong_charset_message(self):
        msg = "WARNING:envelope.message:Cannot decode the message correctly, plain alternative bytes are not in Unicode."
        b = "ř".encode("cp1250")
        e = Envelope(b)
        self.check_lines(e, raises=ValueError)
        with self.assertLogs('envelope', level='WARNING') as cm:
            repr(e)
        self.assertEqual(cm.output, [msg])

        e.header("Content-Type", "text/plain; charset=cp1250")
        e.header("Content-Transfer-Encoding", "base64")
        e.message(b64encode(b), alternative=AUTO)
        self.assertEqual("ř", e.message())

        # Strangely, putting apostrophes around the charset would not work
        # e.header("Content-Type", "text/plain;charset='cp1250'")
        # e._header["Content-Type"] == "text/plain;")

    def test_repr(self):
        e = Envelope("hello").to("test@example.com")
        self.assertEqual('Envelope(to=[test@example.com], message="hello")', repr(e))


class TestSmime(TestAbstract):
    # create a key and its certificate valid for 100 years
    # openssl req -newkey rsa:1024 -nodes -x509 -days 36500 -out certificate.pem

    smime_key = 'tests/smime/key.pem'
    smime_cert = 'tests/smime/cert.pem'
    key_cert_together = Path("tests/smime/key-cert-together.pem")

    def test_smime_sign(self):
        # Message will look that way:
        # MIME-Version: 1.0
        # Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha1"; boundary="----DD291FCCF0F9F19D858D1A9200251EA5"
        #
        # This is an S/MIME signed message
        #
        # ------DD291FCCF0F9F19D858D1A9200251EA5
        #
        # dumb message
        # ------DD291FCCF0F9F19D858D1A9200251EA5
        # Content-Type: application/x-pkcs7-signature; name="smime.p7s"
        # Content-Transfer-Encoding: base64
        # Content-Disposition: attachment; filename="smime.p7s"
        #
        # MIIEggYJKoZIhvcNAQcCoIIEczCCBG8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3
        # DQEHAaCCAmwwggJoMIIB0aADAgECAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkq
        # ... other lines changes every time
        self.check_lines(Envelope(MESSAGE)
                         .smime()
                         .subject("my subject")
                         .reply_to("test-reply@example.com")
                         .signature(Path("tests/smime/key.pem"), cert=Path(self.smime_cert))
                         .send(False),
                         ("Subject: my subject",
                          "Reply-To: test-reply@example.com",
                          MESSAGE,
                          'Content-Disposition: attachment; filename="smime.p7s"',
                          "MIIEUwYJKoZIhvcNAQcCoIIERDCCBEACAQExDzANBglghkgBZQMEAgEFADALBgkq",), 10)

    def test_smime_key_cert_together(self):
        self.check_lines(Envelope(MESSAGE)
                         .smime()
                         .signature(self.key_cert_together)
                         .sign(),
                         ('Content-Disposition: attachment; filename="smime.p7s"',
                          "MIIEUwYJKoZIhvcNAQcCoIIERDCCBEACAQExDzANBglghkgBZQMEAgEFADALBgkq"))

    def test_smime_key_cert_together_passphrase(self):
        self.check_lines(Envelope(MESSAGE)
                         .smime()
                         .signature(Path("tests/smime/key-cert-together-passphrase.pem"), passphrase=GPG_PASSPHRASE)
                         .sign(),
                         ('Content-Disposition: attachment; filename="smime.p7s"',
                          "MIIEUwYJKoZIhvcNAQcCoIIERDCCBEACAQExDzANBglghkgBZQMEAgEFADALBgkq"), 10)

    def test_smime_encrypt(self):
        # Message will look that way:
        # MIME-Version: 1.0
        # Content-Disposition: attachment; filename="smime.p7m"
        # Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m" # note: x- is deprecated and current standard recomends using quotes around smime-type="enveloped-data", without is also accepted
        # Content-Transfer-Encoding: base64
        #
        # MIIBPQYJKoZIhvcNAQcDoIIBLjCCASoCAQAxgfcwgfQCAQAwXTBFMQswCQYDVQQG
        # EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk
        # Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF
        # AASBgHriGJfbxNVpzDhxnObA6q0xoAuXOgYobG5HxpGi9InmlYoWS6ZkeDTMo70B
        # nnXprxG2Q+/0GHJw48R1/B2d4Ln1sYJe5BXl3LVr7QWpwPb+62AZ1TN8793jSic6
        # jBl/v6gDTRoEEjnb8RAkyvDJ7d6OOokgFOfCfTAUOBoZhZrqMCsGCSqGSIb3DQEH
        # ATAUBggqhkiG9w0DBwQIt4seJLnZZW+ACBRKsu4Go7lm
        self.check_lines(Envelope(MESSAGE)
                         .smime()
                         .reply_to("test-reply@example.com")
                         .subject("my message")
                         .encryption(Path(self.smime_cert))
                         .send(False),
                         (
                             'Content-Type: application/pkcs7-mime; smime-type="enveloped-data"; name="smime.p7m"',
                             "Subject: my message",
                             "Reply-To: test-reply@example.com",
                             "Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF",
        ), 10)

    def test_smime_detection(self):
        """ We do not explicitly tell that we are using GPG or S/MIME. """

        # Implicit GPG
        self.check_lines(Envelope(MESSAGE).from_(IDENTITY_2).to(IDENTITY_2)
                         .encryption(key=Path("tests/gpg_keys/envelope-example-identity-2@example.com.key")),
                         result=True)
        self.check_lines(Envelope(MESSAGE).from_(IDENTITY_2).to(IDENTITY_2)
                         .signature(key=Path("tests/gpg_keys/envelope-example-identity-2@example.com.key"), passphrase=GPG_PASSPHRASE),
                         result=True)

        # Implicit S/MIME
        self.check_lines(Envelope(MESSAGE)
                         .subject("my subject")
                         .reply_to("test-reply@example.com")
                         .signature(self.key_cert_together)
                         .send(False),
                         ("Subject: my subject",
                          "Reply-To: test-reply@example.com",
                          MESSAGE,
                          'Content-Disposition: attachment; filename="smime.p7s"',
                          "MIIEUwYJKoZIhvcNAQcCoIIERDCCBEACAQExDzANBglghkgBZQMEAgEFADALBgkq",), 10)
        self.check_lines(Envelope(MESSAGE)
                         .subject("my subject")
                         .reply_to("test-reply@example.com")
                         .encryption(self.key_cert_together)
                         .send(False),
                         (
                             'Content-Type: application/pkcs7-mime; smime-type="enveloped-data"; name="smime.p7m"',
                             "Subject: my subject",
                             "Reply-To: test-reply@example.com",
                             "Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF",
        ), 10)

    def test_multiple_recipients(self):
        # output is generated using pyca cryptography
        from M2Crypto import SMIME
        msg = MESSAGE

        def decrypt(key, cert, text):
            try:
                return Parser(key=key, cert=cert).smime_decrypt(text)
            except SMIME.PKCS7_Error:
                return False

        # encrypt for both keys
        output = (Envelope(msg)
                  .smime()
                  .reply_to("test-reply@example.com")
                  .subject("my message")
                  .encrypt([Path(self.smime_cert), Path("tests/smime/smime-identity@example.com-cert.pem")]))

        # First key
        decrypted_message = decrypt('tests/smime/smime-identity@example.com-key.pem',
                                    'tests/smime/smime-identity@example.com-cert.pem', output).decode('utf-8')
        result = re.search(msg, decrypted_message)
        self.assertTrue(result)

        # Second key
        decrypted_message = decrypt(self.smime_key, self.smime_cert, output).decode('utf-8')
        result = re.search(msg, decrypted_message)
        self.assertTrue(result)

        # encrypt for single key only
        output = (Envelope(msg)
                  .smime()
                  .reply_to("test-reply@example.com")
                  .subject("my message")
                  .encrypt([Path(self.smime_cert)]))

        # Should be false, no search required
        decrypted_message = decrypt('tests/smime/smime-identity@example.com-key.pem',
                                    'tests/smime/smime-identity@example.com-cert.pem', output)
        self.assertFalse(decrypted_message)

        decrypted_message = decrypt(self.smime_key, self.smime_cert, output).decode('utf-8')
        result = re.search(msg, decrypted_message)
        self.assertTrue(result)

    def test_smime_decrypt(self):
        e = Envelope.load(path="tests/eml/smime_encrypt.eml", key=self.smime_key, cert=self.smime_cert)
        self.assertEqual(MESSAGE, e.message())

    def test_smime_decrypt_attachments(self):
        from M2Crypto import BIO, SMIME
        import re
        from base64 import b64encode, b64decode
        body = "an encrypted message with the attachments"  # note that the inline image is not referenced in the text
        encrypted_envelope = (Envelope(body)
                              .smime()
                              .reply_to("test-reply@example.com")
                              .subject("my message")
                              .encryption(Path(self.smime_cert))
                              .attach(path=self.text_attachment)
                              .attach(self.image_file, inline=True)
                              .as_message().as_string()
                              )

        key = self.smime_key
        cert = self.smime_cert

        # # Load private key and cert and decrypt
        s = SMIME.SMIME()
        s.load_key(key, cert)
        p7, data = SMIME.smime_load_pkcs7_bio(BIO.MemoryBuffer(encrypted_envelope.encode('utf-8')))

        # body is in decrypted message
        decrypted_data = s.decrypt(p7).decode('utf-8')
        print(decrypted_data)
        self.assertTrue(re.search(body, decrypted_data))

        # find number of attachments
        attachments = re.findall(r'Content-Disposition: (attachment|inline)', decrypted_data)
        self.assertEqual(2, len(attachments))

        # find number of inline attachments
        inline_attachments = re.findall(r'Content-Disposition: inline', decrypted_data)
        self.assertEqual(1, len(inline_attachments))

        # find inline attachment
        cd_string = 'Content-Disposition: inline'
        pos = decrypted_data.index(cd_string)

        # get only gif data
        data_temp = decrypted_data[pos + len(cd_string):].strip().replace('\n', '').replace('\r', '')
        data_temp = data_temp[:data_temp.index("==") + 2]
        base64_content = b64encode(self.image_file.read_bytes()).decode('ascii')
        self.assertEqual(base64_content, data_temp)

        # find generic.txt attachment
        cd_string = 'Content-Disposition: attachment; filename="generic.txt"'
        pos = decrypted_data.index(cd_string)
        data_temp = decrypted_data[pos:]
        d = data_temp.split('\n\n')[1].strip() + "=="
        attachment_content = b64decode(d).decode('utf-8')

        with open(self.text_attachment, 'r') as f:
            file_content = f.read()

        self.assertEqual(attachment_content, file_content)

    # XX smime_sign.eml is not used right now.
    # Make signature verification possible first.
    # def test_smime_sign(self):
    #     e = Envelope.load(path="tests/eml/smime_sign.eml", key=self.smime_key, cert=self.smime_cert)
    #     self.assertEqual(MESSAGE, e.message())

    def test_smime_key_cert_together(self):
        # XX verify signature
        e = Envelope.load(path="tests/eml/smime_key_cert_together.eml", key=self.key_cert_together)
        self.assertEqual(MESSAGE, e.message())


class TestGPG(TestAbstract):
    # Example identity
    #   envelope-example-identity@example.com
    #   no passphrase
    #   F14F2E8097E0CCDE93C4E871F4A4F26779FA03BB
    # Example identity 2
    #   envelope-example-identity-2@example.com
    #   passphrase: test
    #   3C8124A8245618D286CF871E94CE2905DB00CDB7
    def test_gpg_sign(self):
        # Message will look like this:
        # -----BEGIN PGP SIGNED MESSAGE-----
        # Hash: SHA512
        #
        # dumb message
        # -----BEGIN PGP SIGNATURE-----
        #
        # iQGzBAEBCgAdFiEE8U8ugJfgzN6TxOhx9KTyZ3n6A7sFAl3xGeEACgkQ9KTyZ3n6
        # A7vJawv/Q8+2F4sK/QlLdiOorXx9yhAG3jM/u4N2lr7H5aXDLPF7woYTHB8Gl5My
        # 2+JDSALES0g2JYT6KKpZxHI+0gVEJtT7onsN7k9ye79okzge4wTZqnvf+GQ8xL8F
        # ...
        # Rvf4X8ZB
        # =qCHO
        # -----END PGP SIGNATURE-----

        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .sign(),
                         (MESSAGE,
                          '-----BEGIN PGP SIGNATURE-----',
                          '-----END PGP SIGNATURE-----',), 10)

    def test_gpg_auto_sign(self):
        # mail from "envelope-example-identity@example.com" is in ring
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_("envelope-example-identity@example.com")
                         .sign("auto"),
                         (MESSAGE,
                          '-----BEGIN PGP SIGNATURE-----',
                          '-----END PGP SIGNATURE-----',), 10)

        # mail from "envelope-example-identity-not-stated-in-ring@example.com" should not be signed
        output = str(Envelope(MESSAGE)
                     .gpg(GNUPG_HOME)
                     .from_("envelope-example-identity-not-stated-in-ring@example.com")
                     .sign("auto")).splitlines()
        self.assertNotIn('-----BEGIN PGP SIGNATURE-----', output)

        # force-signing without specifying a key nor sending address should produce a message signed with a first-found key
        output = str(Envelope(MESSAGE)
                     .gpg(GNUPG_HOME)
                     .sign(True)).splitlines()
        self.assertIn('-----BEGIN PGP SIGNATURE-----', output)

        # force-signing without specifying a key and with sending from an e-mail which is not in the keyring must fail
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_("envelope-example-identity-not-stated-in-ring@example.com")
                         .signature(True), raises=RuntimeError)

    def test_gpg_encrypt_message(self):
        # Message will look like this:
        # -----BEGIN PGP MESSAGE-----
        #
        # hQGMA9ig68HPFWOpAQv/dsg8GkPJ9g9HKICe/Hi4AAl0AbAfIvAeKGowHhsvb++G
        # ...
        # s1gZJ8eJEbjGgdtjohAfnr4Qsz1RGwQGcm8DfqzFSnSIUurN21ZYqKjsWpt6s4Dp
        # N0g=
        # =rK+/
        # -----END PGP MESSAGE-----

        message = (Envelope(MESSAGE)
                   .gpg(GNUPG_HOME)
                   .from_(IDENTITY_1)
                   .to(IDENTITY_2)
                   .encrypt())
        self.check_lines(message, (PGP_MESSAGE,), 10)

        self.assertIn(MESSAGE, self.bash("gpg", "--decrypt", piped=str(message), envelope=False))

    def test_gpg_encrypt(self):
        # Message will look like this:
        # ****************************************************************************************************
        # Have not been sent from envelope-example-identity@example.com to envelope-example-identity-2@example.com
        # Encrypted subject: None
        # Encrypted message: b'message'
        #
        # Subject: Encrypted message
        # MIME-Version: 1.0
        # Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";
        #  boundary="===============1001129828818615570=="
        # From: envelope-example-identity@example.com
        # To: envelope-example-identity-2@example.com,envelope-example-identity-2@example.com
        # Date: Wed, 11 Dec 2019 17:56:03 +0100
        # Message-ID: <157608336314.13303.1097227818284823500@promyka>
        #
        # --===============1001129828818615570==
        # Content-Type: application/pgp-encrypted
        #
        # Version: 1
        # --===============1001129828818615570==
        # Content-Type: application/octet-stream; name="encrypted.asc"
        # Content-Description: OpenPGP encrypted message
        # Content-Disposition: inline; filename="encrypted.asc"
        #
        # -----BEGIN PGP MESSAGE-----
        # ...
        # -----END PGP MESSAGE-----
        #
        # --===============1001129828818615570==--

        e = str(Envelope(MESSAGE)
                .to(IDENTITY_2)
                .gpg(GNUPG_HOME)
                .from_(IDENTITY_1)
                .subject("dumb subject")
                .encryption())

        self.check_lines(e,
                         ("Encrypted subject: dumb subject",
                          "Encrypted message: dumb message",
                          "Subject: Encrypted message",
                          'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";',
                          "From: envelope-example-identity@example.com",
                          "To: envelope-example-identity-2@example.com",
                          ), 10, not_in='Subject: dumb subject')

        lines = e.splitlines()
        message = "\n".join(lines[lines.index(PGP_MESSAGE):])
        self.check_lines(self.bash("gpg", "--decrypt", piped=message, envelope=False),
                         ('Content-Type: multipart/mixed; protected-headers="v1";',
                          'Subject: dumb subject',
                          'Content-Type: text/plain; charset="utf-8"',
                          MESSAGE
                          ))

    def test_arbitrary_encrypt(self):
        """ Keys to be encrypted with explicitly chosen  """
        temp = [TemporaryDirectory() for _ in range(4)]  # must exist in the scope to preserve the dirs
        rings = [t.name for t in temp]
        message = MESSAGE
        key1_raw = Path("tests/gpg_keys/envelope-example-identity@example.com.bytes.key").read_bytes()
        key1_armored = Path("tests/gpg_keys/envelope-example-identity@example.com.key").read_text()
        _importer = Envelope("just importer")

        # helper methods
        def decrypt(s, ring, equal=True):
            m = self.assertEqual if equal else self.assertNotEqual
            m(message, Envelope.load(s, gnupg_home=rings[ring]).message())

        def importer(ring, key, passphrase=None):
            _importer.gpg(rings[ring]).sign(Path("tests/gpg_keys/" + key), passphrase=passphrase)

        # Message encrypted for envelope-example-identity@example.com only, not for the sender
        e1 = str(Envelope(message)
                 .to(IDENTITY_1)
                 .gpg(GNUPG_HOME)
                 .from_(IDENTITY_2)
                 .subject("dumb subject")
                 .encryption(IDENTITY_1).as_message())

        # message is decipherable only from the keyring the right key is in
        self.assertEqual(message, Envelope.load(e1, gnupg_home=(GNUPG_HOME)).message())
        decrypt(e1, 0, False)
        # importing other key does not help
        importer(0, "envelope-example-identity-2@example.com.key", GPG_PASSPHRASE)
        decrypt(e1, 0, False)
        # importing the right key does help
        importer(0, "envelope-example-identity@example.com.key")
        decrypt(e1, 0)

        # message encrypted for multiple recipients
        e2 = str(Envelope(message)
                 .to(IDENTITY_1)
                 .gpg(GNUPG_HOME)
                 .from_(IDENTITY_3)
                 .encryption([IDENTITY_1, IDENTITY_2])
                 .as_message())

        decrypt(e2, 1, False)
        importer(1, "envelope-example-identity-2@example.com.key", GPG_PASSPHRASE)
        decrypt(e2, 1)
        importer(2, "envelope-example-identity@example.com.key", GPG_PASSPHRASE)
        decrypt(e2, 2)

        # message not encrypted for a recipient but for a sender only (for some unknown reason)
        e3 = str(Envelope(message)
                 .to(IDENTITY_2)
                 .gpg(GNUPG_HOME)
                 .from_(IDENTITY_1)
                 .encryption([IDENTITY_1, ])
                 .as_message())

        decrypt(e3, 1, False)  # ring 1 has "envelope-example-identity-2@example.com"
        decrypt(e3, 2)  # ring 2 has "envelope-example-identity@example.com"

        # message encrypted for combination of fingerprints and e-mails
        e3 = str(Envelope(message)
                 .to("envelope-example-identity-3@example.com, envelope-example-identity@example.com")
                 .gpg(GNUPG_HOME)
                 .from_(IDENTITY_2)
                 .encryption([IDENTITY_2, IDENTITY_1_GPG_FINGERPRINT])
                 .as_message())

        decrypt(e3, 0)  # ring 0 has both
        decrypt(e3, 1)  # ring 1 has "envelope-example-identity-2@example.com"
        decrypt(e3, 2)  # ring 2 has "envelope-example-identity@example.com"
        decrypt(e3, 3, False)  # ring 3 has none

        # trying to encrypt with an unknown key while/without specifying decipherers explicitly
        # (note that we pass a generator to the .encryption to test if it takes other iterables than a list)
        for e in [Envelope(message).encryption(x for x in [IDENTITY_3, IDENTITY_1_GPG_FINGERPRINT]),
                  Envelope(message).encryption()]:
            with self.assertLogs('envelope', level='WARNING') as cm:
                self.assertEqual('None', str(e
                                             .to(f"{IDENTITY_3}, {IDENTITY_1}")
                                             .from_(IDENTITY_2)
                                             .gpg(GNUPG_HOME)
                                             .as_message()))
                self.assertIn(f'WARNING:envelope.envelope:Key for {IDENTITY_3} seems missing,'
                              f' see: GNUPGHOME=tests/gpg_ring/ gpg --list-keys', cm.output)
                self.assertIn('ERROR:envelope.envelope:Signing/encrypting failed.', cm.output)
                self.assertNotIn(f'WARNING:envelope.envelope:Key for {IDENTITY_2} seems missing', cm.output)

        # import raw unarmored key in a list ("envelope-example-identity@example.com" into ring 1)
        # (note that we pass a set to the .encryption to test if it takes other iterables than a list)
        e4 = Envelope(message).encryption({IDENTITY_2, key1_raw}).to(IDENTITY_3).from_(IDENTITY_2).gpg(
            rings[1]).as_message()
        decrypt(e4, 1)
        decrypt(e4, 2)

        # multiple encryption keys in bash
        def bash(ring, from_, to, encrypt, valid=True):
            contains = PGP_MESSAGE if valid else "Signing/encrypting failed."
            self.assertIn(contains, self.bash("--from", from_, "--to", *to, "--encrypt", *encrypt, piped=message,
                                              env={"GNUPGHOME": rings[ring]}))

        bash(1, IDENTITY_1, (IDENTITY_2,), ())  # ring 1 has both
        bash(1, IDENTITY_1, (IDENTITY_2,), (IDENTITY_2,))
        # not specifying the exact encryption identities leads to an error
        bash(0, IDENTITY_1, (IDENTITY_2, IDENTITY_3), (), False)  # ring 0 has both, but misses ID=3
        bash(0, IDENTITY_1, (IDENTITY_2, IDENTITY_3), (IDENTITY_1, IDENTITY_2))
        bash(3, IDENTITY_1, (IDENTITY_2,), (), False)  # ring 3 has none
        bash(3, IDENTITY_1, (IDENTITY_2, IDENTITY_3), (key1_armored,))  # insert ID=1 into ring 3
        bash(3, IDENTITY_2, (IDENTITY_1,), (), False)  # ID=2 still misses in ring 3
        bash(3, IDENTITY_2, (IDENTITY_1,), ("--no-from",))  # --no-sender supress the need for ID=2

    def test_arbitrary_encrypt_with_signing(self):
        model = (Envelope(MESSAGE)
                 .to(f"{IDENTITY_3}, {IDENTITY_1}")
                 .from_(IDENTITY_2)
                 .gpg(GNUPG_HOME))

        def logged(signature, encryption, warning=False):
            e = (model.copy().signature(signature).encryption(encryption))
            if warning:
                with self.assertLogs('envelope', level='WARNING') as cm:
                    self.assertEqual("", str(e))
                    self.assertIn(warning, str(cm.output))
            else:
                self.assertIn(PGP_MESSAGE, str(e))

        logged(False, [IDENTITY_3, "invalid"],
               f'WARNING:envelope.envelope:Key for {IDENTITY_3},'
               ' invalid seems missing, see: GNUPGHOME=tests/gpg_ring/ gpg --list-keys')
        logged(False, [IDENTITY_1])
        logged(IDENTITY_1, [IDENTITY_1])
        logged(IDENTITY_3, [IDENTITY_1],
               f'WARNING:envelope.envelope:The secret key for {IDENTITY_3} seems to not be used,'
               f" check if it is in the keyring: GNUPGHOME=tests/gpg_ring/ gpg --list-secret-keys")
        logged(IDENTITY_3, False,
               f'WARNING:envelope.envelope:The secret key for {IDENTITY_3} seems to not be used,'
               f" check if it is in the keyring: GNUPGHOME=tests/gpg_ring/ gpg --list-secret-keys")

        self.assertEqual("", str(model.copy().encrypt(IDENTITY_2, sign=IDENTITY_3)))
        self.assertIn(PGP_MESSAGE, str(model.copy().encrypt(IDENTITY_2, sign=IDENTITY_1)))

    def test_gpg_auto_encrypt(self):
        # mail `from` "envelope-example-identity@example.com" is in ring
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_(IDENTITY_1)
                         .to(IDENTITY_1)
                         .encrypt("auto"),
                         (PGP_MESSAGE,
                          '-----END PGP MESSAGE-----',), (10, 15), not_in=MESSAGE)

        # mail `to` "envelope-unknown@example.com" unknown, must be both signed and encrypted
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_(IDENTITY_1)
                         .to(IDENTITY_2)
                         .signature("auto")
                         .encrypt("auto"),
                         (PGP_MESSAGE,
                          '-----END PGP MESSAGE-----',), 20, not_in=MESSAGE)

        # mail `from` "envelope-unknown@example.com" unknown, must not be encrypted
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_("envelope-unknown@example.com")
                         .to(IDENTITY_1)
                         .encrypt("auto"),
                         (MESSAGE,), (0, 2), not_in=PGP_MESSAGE)

        # mail `to` "envelope-unknown@example.com" unknown, must not be encrypted
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_(IDENTITY_1)
                         .to("envelope-unknown@example.com")
                         .encrypt("auto"),
                         (MESSAGE,), (0, 2), not_in=PGP_MESSAGE)

        # force-encrypting without having key must return empty response
        self.check_lines(Envelope(MESSAGE)
                         .gpg(GNUPG_HOME)
                         .from_(IDENTITY_1)
                         .to("envelope-unknown@example.com")
                         .encryption(True), longer=(0, 1), result=False)

    def test_gpg_sign_passphrase(self):
        self.check_lines(Envelope(MESSAGE)
                         .to(IDENTITY_2)
                         .gpg(GNUPG_HOME)
                         .from_(IDENTITY_1)
                         .signature("3C8124A8245618D286CF871E94CE2905DB00CDB7", GPG_PASSPHRASE),  # passphrase needed
                         ("-----BEGIN PGP SIGNATURE-----",), 10)

    def test_auto_import(self):
        temp = TemporaryDirectory()

        # no signature - empty ring
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .signature(),
                         raises=RuntimeError)

        # import key to the ring
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .sign(Path("tests/gpg_keys/envelope-example-identity@example.com.key")),
                         (MESSAGE,
                          '-----BEGIN PGP SIGNATURE-----',
                          '-----END PGP SIGNATURE-----',), 10)

        # key in the ring from last time
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .signature(),
                         (MESSAGE,
                          '-----BEGIN PGP SIGNATURE-----',
                          '-----END PGP SIGNATURE-----',), 10)

        # cannot encrypt for identity-2
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .from_(IDENTITY_1)
                         .to(IDENTITY_2)
                         .encryption(),
                         result=False)

        # signing should fail since we have not imported key for identity-2
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .from_(IDENTITY_2)
                         .signature(),
                         raises=RuntimeError)

        # however it should pass when we explicitly use an existing GPG key to be signed with
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .from_(IDENTITY_2)
                         .signature(IDENTITY_1_GPG_FINGERPRINT),
                         (MESSAGE,
                          '-----BEGIN PGP SIGNATURE-----',
                          '-----END PGP SIGNATURE-----',), 10, result=True)

        # import encryption key - no passphrase needed while importing or using public key
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .from_(IDENTITY_1)
                         .to(IDENTITY_2)
                         .encryption(Path("tests/gpg_keys/envelope-example-identity-2@example.com.key")),
                         result=True)

        # signing with an invalid passphrase should fail for identity-2
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .from_(IDENTITY_2)
                         .signature(passphrase="INVALID PASSPHRASE"),
                         result=False)

        # signing with a valid passphrase should pass
        self.check_lines(Envelope(MESSAGE)
                         .gpg(temp.name)
                         .from_(IDENTITY_2)
                         .signature(passphrase=GPG_PASSPHRASE),
                         result=True)

    def test_signed_gpg(self):
        # XX we should test signature verification with e._gpg_verify(),
        # however .load does not load application/pgp-signature content at the moment
        e = Envelope.load(path="tests/eml/test_signed_gpg.eml")
        self.assertEqual(MESSAGE, e.message())

    def test_encrypted_gpg(self):
        e = Envelope.load(path="tests/eml/test_encrypted_gpg.eml")
        self.assertEqual("dumb encrypted message", e.message())

    def test_encrypted_signed_gpg(self):
        e = Envelope.load(path="tests/eml/test_encrypted_signed_gpg.eml")
        self.assertEqual("dumb encrypted and signed message", e.message())

    def test_encrypted_gpg_subject(self):
        body = "just a body text"
        subject = "This is an encrypted subject"
        encrypted_subject = "Encrypted message"
        ref = (Envelope(body)
               .gpg(GNUPG_HOME)
               .to(IDENTITY_2)
               .from_(IDENTITY_1)
               .encryption())
        encrypted_eml = ref.subject(subject).as_message().as_string()

        # subject has been encrypted
        self.assertIn("Subject: " + encrypted_subject, encrypted_eml)
        self.assertNotIn(subject, encrypted_eml)

        # subject has been decrypted
        e = Envelope.load(encrypted_eml)
        self.assertEqual(body, e.message())
        self.assertEqual(subject, e.subject())

        # further meddling with the encrypt parameter
        def check_decryption(reference, other_subject=encrypted_subject):
            encrypted = reference.as_message().as_string()
            self.assertIn(other_subject, encrypted)
            self.assertNotIn(subject, encrypted)

            decrypted = Envelope.load(encrypted).as_message().as_string()
            self.assertIn(subject, decrypted)
            self.assertNotIn(other_subject, decrypted)

        front_text = "Front text"
        check_decryption(ref.subject(subject, encrypted=True))  # the default behaviour
        check_decryption(ref.subject(subject, front_text), front_text)  # choose another placeholder text

        always_visible = ref.subject(subject, encrypted=False).as_message().as_string()  # do not encrypt the subject
        self.assertIn(subject, always_visible)
        self.assertIn(subject, Envelope.load(always_visible).as_message().as_string())

    def test_long_attachment_filename(self):
        """
        When whole message gets output, Message.as_string() produces this (unfold header):
            Content-Type: text/plain
            Content-Transfer-Encoding: base64
            Content-Disposition: attachment; filename="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            MIME-Version: 1.0

        When only part of the message gets output, Message.get_payload()[0].as_string() produces this (fold header):
            Content-Type: text/plain
            Content-Transfer-Encoding: base64
            Content-Disposition: attachment;
            filename="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            MIME-Version: 1.0

        This behaviour is observed when GPG signing attachments with file names longer than 34 chars.
        Envelope corrects this behaviour when sending or outputting.
        However, if the user uses Envelope.as_message(), its gets the underlying Message without the correction with GPG void.
        See #19 and https://github.com/python/cpython/issues/99533
        """
        e = (Envelope(MESSAGE)
             .to(IDENTITY_2)
             .gpg(GNUPG_HOME)
             .from_(IDENTITY_1)
             .signature("3C8124A8245618D286CF871E94CE2905DB00CDB7", GPG_PASSPHRASE)
             .attach("some data", name="A"*35))

        def verify_inline_message(txt: str):
            boundary = re.search(r'boundary="(.*)"', txt).group(1)
            reg = (fr'{boundary}.*{boundary}\n(.*)\n--{boundary}.*(-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----)')
            m = re.search(reg, txt, re.DOTALL)
            return e._gpg_verify(m[2].encode(), m[1].encode())

        # accessing via standard email package with get_payload called on different parts keeps signature
        sig = e.as_message().get_payload()[1].get_payload().encode()
        data = e.as_message().get_payload()[0].as_bytes()
        self.assertTrue(e._gpg_verify(sig, data))

        # accessing via standard email package on the whole message does not keep signature
        # When this test fails it means the Python package was corrected. Good news! Let's get rid of #19 mocking.
        self.assertFalse(verify_inline_message(e.as_message().as_string()))

        # envelope corrects this behaviour when accessed via bytes
        self.assertTrue(verify_inline_message(bytes(e).decode()))

        # envelope corrects this behaviour when accessed via str
        self.assertTrue(verify_inline_message(str(e)))

        # envelope corrects this behaviour when sending
        def check_sending(o, email, **_):
            self.assertTrue(verify_inline_message(e.as_message().as_string()))
        with mock.patch.object(SMTPHandler, 'send_message', check_sending):
            e.send()


class TestMime(TestAbstract):
    plain = """First
Second
Third
    """

    html = """First<br>
Second
Third
    """

    html_without_line_break = """<b>First</b>
Second
Third
    """

    mime_plain = 'Content-Type: text/plain; charset="utf-8"'
    mime_html = 'Content-Type: text/html; charset="utf-8"'

    def test_plain(self):
        pl = self.mime_plain
        self.check_lines(Envelope().message(self.plain).mime("plain", "auto"), pl)
        self.check_lines(Envelope().message(self.plain), pl)
        self.check_lines(Envelope().message(self.html).mime("plain"), pl)

    def test_html(self):
        m = self.mime_html
        self.check_lines(Envelope().message(self.plain).mime("html", "auto"), m)
        self.check_lines(Envelope().message(self.html), m)
        self.check_lines(Envelope().message(self.html_without_line_break), m)

    def test_nl2br(self):
        nobr = "Second"
        br = "Second<br>"
        self.check_lines(Envelope().message(self.html),
                         nobr)  # there already is a <br> tag so nl2br "auto" should not convert it
        self.check_lines(Envelope().message(self.html).mime(nl2br=True), br)

        self.check_lines(Envelope().message(self.html_without_line_break), br)
        self.check_lines(Envelope().message(self.html_without_line_break).mime("plain", True),
                         nobr)  # nl2br disabled in "plain"
        self.check_lines(Envelope().message(self.html_without_line_break).mime(nl2br=False), nobr)

    def test_alternative(self):
        boundary = "=====envelope-test===="

        # alternative="auto" can become both "html" and "plain"
        e1 = Envelope().message("He<b>llo</b>").message("Hello", alternative="plain", boundary=boundary).date(False)
        e2 = Envelope().message("He<b>llo</b>", alternative="html").message("Hello", boundary=boundary).date(False)
        self.assertEqual(e1, e2)

        # HTML variant is always the last even if defined before plain variant
        self.check_lines(e1, ('Content-Type: text/plain; charset="utf-8"',
                              "Hello",
                              'Content-Type: text/html; charset="utf-8"',
                              "He<b>llo</b>"))

    def test_only_2_alternatives_allowed(self):
        e1 = Envelope().message("He<b>llo</b>").message("Hello", alternative="plain")
        # we can replace alternative
        e1.copy().message("Test").message("Test", alternative="plain")

        # but in the moment we set all three and call send or preview, we should fail
        self.assertRaises(ValueError, e1.copy().message("Test", alternative="html").preview)

    def test_libmagic(self):
        """" Should pass with either python-magic or file-magic library installed on the system #25 """
        # directly test get_mimetype layer
        self.assertEqual("text/html", get_mimetype(data=b"<!DOCTYPE html>hello"))
        self.assertEqual("image/gif", get_mimetype(path=self.image_file))

        # test get_mimetype in the action while dealing attachments
        e = (Envelope()
             .attach("hello", "text/plain")
             .attach(b"hello bytes")
             .attach(Path("tests/gpg_ring/trustdb.gpg"))
             .attach(b"<!DOCTYPE html>hello")
             .attach("<!DOCTYPE html>hello")
             .attach(self.image_file))
        self.assertListEqual(["text/plain", "text/plain", "application/octet-stream",
                             "text/html", "text/html", "image/gif"],
                             [a.mimetype for a in e.attachments()])


class TestRecipients(TestAbstract):
    def test_from(self):
        id1 = "identity-1@example.com"
        id2 = "identity-2@example.com"
        self.check_lines(Envelope(MESSAGE).header("sender", id1),
                         f"sender: {id1}", not_in=f"From: {id1}")
        self.check_lines(Envelope(MESSAGE, headers=[("sender", id1)]),
                         f"sender: {id1}", not_in=f"From: {id1}")

        self.check_lines(Envelope(MESSAGE, from_=id1),
                         f"From: {id1}", not_in=f"Sender: {id1}")
        self.check_lines(Envelope(MESSAGE).from_(id1),
                         f"From: {id1}", not_in=f"Sender: {id1}")

        self.check_lines(Envelope(MESSAGE)
                         .from_(id1)
                         .header("Sender", id2),
                         (f"From: {id1}", f"Sender: {id2}"))
        self.check_lines(Envelope(MESSAGE)
                         .header("Sender", id2)
                         .from_(id1),
                         (f"From: {id1}", f"Sender: {id2}"))

    def test_from_addr(self):
        mail1 = "envelope-from@example.com"
        mail2 = "header-from@example.com"
        e = Envelope(MESSAGE).from_addr(mail1).from_(mail2)
        self.assertEqual(mail1, e.from_addr())
        self.assertEqual(mail2, e.from_())
        self.assertIn("Have not been sent from " + mail1, str(e.send(False)))
        e = Envelope(MESSAGE).from_(mail2)
        self.assertIn("Have not been sent from " + mail2, str(e.send(False)))
        e = Envelope(MESSAGE, from_addr=mail1).from_(mail2)
        self.assertIn("Have not been sent from " + mail1, str(e.send(False)))
        self.assertIn("Have not been sent from " + mail1, self.bash("--from-addr", mail1, "--send", "0", file=self.eml))

    def test_addresses(self):
        e = Envelope.load(path=self.eml)
        self.assertEqual(1, len(e.to()))
        contact = e.to()[0]
        full = "Person <person@example.com>"
        self.assertEqual(full, contact)
        self.assertEqual("person@example.com", contact)
        self.assertEqual("person@example.com", contact.address)
        self.assertEqual("Person", contact.name)
        self.assertEqual("PERSON@examPLE.com", contact)
        self.assertEqual(Address("another name <PERSON@examPLE.com>"), contact)
        self.assertNotEqual("person2@example.com", contact)
        self.assertNotEqual(Address("another name <person2@example.com>"), contact)

        # host property
        self.assertEqual("example.com", contact.host)
        self.assertNotEqual("@example.com", contact.host)

        # user property
        self.assertEqual("person", contact.user)
        self.assertNotEqual("PERSON", contact.user)

        # Address is correctly typed, empty properties returns string
        empty = Address()
        self.assertEqual(Address(""), empty)
        self.assertEqual("", str(empty.user))
        self.assertEqual("", str(empty.host))
        self.assertEqual(str, type(empty.address))
        self.assertEqual(str, type(empty.name))
        self.assertEqual(Address, type(empty))
        self.assertFalse(bool(empty))
        self.assertTrue(bool(contact))

        # joining
        self.assertEqual(f"{full}, {full}", ", ".join((contact, contact)))

        # casefold method
        c = contact.casefold()
        self.assertEqual(contact, c)
        self.assertIsNot(contact, c)
        self.assertEqual(c.name, "person")
        self.assertNotEqual(c.name, contact.name)

    def test_disguised_addresses(self):
        """ Malware actors use at-sign at the addresses to disguise the real e-mail.

        Python standard library is not perfect – it has troubles to parse
         well-formed but exotic addresses.
        The best solution would be to ameliorate the standard library.
        However, such task is too complex. Envelope wants to be slightly better
         and fix some of the use cases the standard library fails.
         """

        # These checks represent the email.utils behaviour that I consider buggy.
        # If any of these tests fails, it's a good message the underlying Python libraries are better
        # and we may stop remedying.
        # https://github.com/python/cpython/issues/40889#issuecomment-1094001067

        if sys.version_info < (3, 11):
            return

        disguise_addr = "first@example.cz <second@example.com>"
        same = "person@example.com <person@example.com>"
        self.assertEqual(('', 'first@example.cz'), _parseaddr(disguise_addr))
        self.assertEqual([('', 'first@example.cz'), ('', 'second@example.com')],
                         _getaddresses([disguise_addr]))
        self.assertEqual([('', 'person@example.com'), ('', 'person@example.com')],
                         _getaddresses([same]))

        # For the same input, Envelope receives better results.
        self.assertEqual(Address(name='first@example.cz', address='second@example.com'), Address(disguise_addr))
        self.assertEqual(Address(name='first@example.cz', address='second@example.com'),
                         Address.parse(disguise_addr, single=True))
        self.assertEqual(Address(name='first@example.cz', address='second@example.com'),
                         Address.parse(disguise_addr)[0])
        self.assertEqual(Address(address='person@example.com'), Address(same))
        self.assertEqual(Address(address='person@example.com'), Address.parse(same)[0])
        self.assertEqual(Address(address='person@example.com'), Address.parse(same, single=True))

        # Try various disguised addresses
        examples = ["person@example.com <person@example.com>",  # the same
                    "person@example.com <person@example2.com>",  # differs, the name hiding the address
                    "pers'one'@'ample.com <a@example.com>",  # single address
                    "pers'one'@'ample.com, <a@example.com>",  # two addresses
                    "alone@example.com",
                    "John Smith <john.smith@example.com>",
                    # a lot of addresses, different delimiters
                    'User ((nested comment))<foo@bar.com> example@example.com ; test@example.com , hello <another@dom.com>',
                    # one of them is disguised
                    'User ((nested comment))<foo@bar.com> example@example.com ; test@example.com;hello<another@dom.cz> , ugly@example.com <another@example.com>',
                    # three of them are disguised
                    'ug@ly3@example.com <another3@example.com> ,ugly2@example.com <another2@example.com> , ugly@example.com <another@example.com>']

        expected_parseaddr = [("", "person@example.com"),
                              ("person--AT--example.com", "person@example2.com"),
                              ("pers'one'--AT--'ample.com", "a@example.com"),
                              ("", "pers'one'@'ample.com"),
                              ("", "alone@example.com"),
                              ("John Smith", "john.smith@example.com"),
                              ("User (nested comment)", "foo@bar.com"),
                              ("User (nested comment)", "foo@bar.com"),
                              ("ug--AT--ly3--AT--example.com", "another3@example.com")]

        expected_getaddresses = [
            [("", "person@example.com")],
            [("person--AT--example.com", "person@example2.com")],
            [("pers'one'--AT--'ample.com", "a@example.com")],
            [("", "pers'one'@'ample.com"),
             ("", "a@example.com")],
            [("", "alone@example.com")],
            [("John Smith", "john.smith@example.com")],
            [("User (nested comment)",  "foo@bar.com"),
             ("",  "example@example.com"),
             ("", "test@example.com"),
             ("hello", "another@dom.com")],
            [("User (nested comment)", "foo@bar.com"),
             ("",  "example@example.com"),
             ("", "test@example.com"),
             ("hello",  "another@dom.cz"),
             ("ugly--AT--example.com", "another@example.com")],
            [("ug--AT--ly3--AT--example.com", "another3@example.com"),
             ("ugly2--AT--example.com", "another2@example.com"),
             ("ugly--AT--example.com", "another@example.com")]]

        for e, r in zip(expected_parseaddr, (Address(e) for e in examples)):
            name, addr = e
            self.assertEqual(Address(name=name, address=addr), r)

        for e, r in zip(expected_getaddresses, (Address.parse(e) for e in examples)):
            expected = [Address(name=name, address=addr) for name, addr in e]
            self.assertEqual(expected, r)

        # As we want to be slightly better than the standard library
        # and not better in some cases and worse than others.
        # So we take the original test cases from the standard library
        # and try them – they should return the same results in Envelope.
        # https://github.com/python/cpython/blob/main/Lib/test/test_email/test_email.py

        def check(addresses, models):
            """ Parsing addresses is exactly the same as in the standard email.utils library. """
            compared = [Address(name=v[0], address=v[1]) for v in models if v[0] or v[1]]
            parsed = Address.parse(addresses)
            self.assertEqual([(a.name, a.address) for a in parsed],
                             [(a.name, a.address) for a in compared])
        check(['aperson@dom.ain (Al Person)',
               'Bud Person <bperson@dom.ain>'],
              [('Al Person', 'aperson@dom.ain'),
               ('Bud Person', 'bperson@dom.ain')])

        check(['foo: ;'], [('', '')])
        check(
            ['[]*-- =~$'],
            [('', ''), ('', ''), ('', '*--')])
        check(
            ['foo: ;', '"Jason R. Mastaler" <jason@dom.ain>'],
            [('', ''), ('Jason R. Mastaler', 'jason@dom.ain')])

        """Test proper handling of a nested comment"""
        check(['User ((nested comment)) <foo@bar.com>'], [('User (nested comment)', 'foo@bar.com')])

        """Test the handling of a Header object."""
        check(['Al Person <aperson@dom.ain>'], [('Al Person', 'aperson@dom.ain')])

    def test_removing_contact(self):
        contact = "Person2 <person2@example.com>"

        def e():
            return Envelope.load(path=self.eml).cc(contact)

        # Original contact should be removed
        self.assertFalse(e().to(False).to())
        self.assertFalse(e().to("").to())
        self.assertFalse(e().to([False]).to())
        self.assertFalse(e().to([""]).to())

        # Contact should be inserted
        self.assertEqual(contact, e().to(["", contact]).to()[0])
        self.assertEqual(contact, e().to([contact, False]).to()[0])
        self.assertEqual(1, len(e().to([contact, False]).to()))

        # Cc should stay intact
        self.assertEqual([contact], e().to("").cc())

        # Works from bash too
        header_row = f"To: Person <person@example.com>"
        self.assertIn(header_row, self.bash(file=self.eml))
        self.assertNotIn(header_row, self.bash("--to", "", file=self.eml))
        self.assertNotIn(f"To: {contact}", self.bash("--to", "", "contact", file=self.eml))

    def test_reading_contact(self):
        self.assertIn("Person <person@example.com>", self.bash("--to"))
        self.assertIn("Harry Potter Junior via online--hey-list-open <some-list-email-address@example.com>",
                      self.bash("--from"))

        # if multiple recipients encountered, each displayed on its own line
        self.assertIn("Person <person1@example.com>\nPerson2 <person2@example.com>",
                      self.bash("--to", file=self.charset))
        self.assertIn("Person3 <person3@example.com>\nPerson4 <person4@example.com>",
                      self.bash("--cc", file=self.charset))
        self.assertIn("Person5 <person5@example.com>", self.bash("--bcc", file=self.charset))
        self.assertIn("Person6 <person6@example.com>", self.bash("--reply-to", file=self.charset))

    def test_empty_contact(self):
        """ Be sure to receive an address even if the header misses. """
        e1 = Envelope.load("Empty message")
        self.assertTrue(isinstance(e1.from_(), Address))
        self.assertTrue(isinstance(e1.to(), list))
        self.assertTrue(isinstance(e1.cc(), list))
        self.assertTrue(isinstance(e1.bcc(), list))
        self.assertTrue(isinstance(e1.reply_to(), list))

        self.assertFalse(e1.from_())

        self.assertEqual("", e1.from_().address)

        e2 = Envelope.load("From: test@example.com\n\nEmpty message")
        self.assertTrue(isinstance(e2.from_(), Address))
        self.assertTrue(e2.from_())
        self.assertTrue(e2.header("from"))
        self.assertTrue(e2.header("From"))
        self.assertFalse(e2.header("sender"))
        self.assertEqual("", e2.from_().name)

        e3 = Envelope.load("From: Person <test@example.com>\n\nEmpty message")
        self.assertTrue(e3.from_())
        self.assertEqual("Person", e3.from_().name)
        self.assertTrue(e3.from_().is_valid())

        e4 = Envelope.load("From: Invalid\n\nEmpty message")
        self.assertTrue(e4.from_())
        self.assertEqual("Invalid", e4.from_().address)
        self.assertEqual("", e4.from_().name)
        self.assertFalse(e4.from_().is_valid())

    def test_multiple_recipients_format(self):
        """ You can use iterables like tuple, list, generator, set, frozenset for specifying multiple values """
        one = [IDENTITY_1]
        two = [IDENTITY_1, IDENTITY_2]
        three = [IDENTITY_1, IDENTITY_2, IDENTITY_3]

        # try single value, tuple and list
        self.assertEqual(one, Envelope(MESSAGE).to(IDENTITY_1).to())
        self.assertEqual(one, Envelope(MESSAGE).to((IDENTITY_1,)).to())
        self.assertEqual(two, Envelope(MESSAGE).to([IDENTITY_1, IDENTITY_2]).to())
        self.assertEqual(two, Envelope(MESSAGE).to((IDENTITY_1, IDENTITY_2)).to())
        # try single string with multiple recipients
        self.assertEqual(two, Envelope(MESSAGE).to(f"{IDENTITY_1}, {IDENTITY_2}").to())
        self.assertEqual(two, Envelope(MESSAGE).to(f"{IDENTITY_1}; {IDENTITY_2}").to())
        self.assertEqual(three, Envelope(MESSAGE).to((f"{IDENTITY_1}; {IDENTITY_2}", IDENTITY_3)).to())
        # try generator
        self.assertEqual(two, Envelope(MESSAGE).to(x for x in (IDENTITY_1, IDENTITY_2)).to())
        # try set, frozenset
        self.assertEqual(set(two), set(Envelope(MESSAGE).to({IDENTITY_1, IDENTITY_2}).to()))
        self.assertEqual(set(two), set(Envelope(MESSAGE).to({IDENTITY_1, IDENTITY_2}).to(IDENTITY_1).to()))
        self.assertEqual(set(three), set(Envelope(MESSAGE).to({IDENTITY_1, IDENTITY_2}).to(IDENTITY_3).to()))
        self.assertEqual(set(two), set(Envelope(MESSAGE).to(frozenset([IDENTITY_1, IDENTITY_2])).to()))


class TestSubject(TestAbstract):
    def test_cache_recreation(self):
        s1 = "Test"
        s2 = "Another"
        e = Envelope(MESSAGE).subject(s1)
        self.check_lines(e, f"Subject: {s1}")

        e.subject(s2)
        self.check_lines(e, f"Subject: {s2}")


class TestHeaders(TestAbstract):
    def test_generic_header_manipulation(self):
        # Add a custom header and delete it
        e = Envelope(MESSAGE).subject("my subject").header("custom", "1")
        self.assertEqual(e.header("custom"), "1")
        self.assertIs(e.header("custom", replace=True), e)

        # Add a header multiple times
        e.header("custom", "2").header("custom", "3")
        # Receive list
        self.assertEqual(e.header("custom"), ["2", "3"])
        # Replace by single value
        self.assertIs(e.header("custom", "4", replace=True), e)
        # Receive string
        self.assertEqual(e.header("custom"), "4")
        # Delete the header and read None
        self.assertIs(e.header("custom", None, replace=True), e)
        self.assertIs(e.header("custom"), None)

    def test_specific_header_manipulation(self):
        """ Specific headers are stored in instance attributes
            Ex: It is useful to have Subject as a special header since it can be encrypted.
            Ex: It is useful to have Cc as a special header since it can hold the list of receivers.
        """
        # Add a specific header like and delete it
        s = "my subject"
        id1 = "person@example.com"
        id2 = "person2@example.com"
        id3 = "person3@example.com"
        e = Envelope(MESSAGE) \
            .subject(s) \
            .header("custom", "1") \
            .cc(id1)  # set headers via their specific methods
        self.assertEqual(s, e.header("subject"))  # access via .header
        self.assertEqual(s, e.subject())  # access via specific method .subject
        self.assertIs(e, e.header("subject", replace=True))
        self.assertIs("", e.header("subject"))
        self.assertEqual(s, e.header("subject", s).subject())  # set via generic method

        self.assertEqual([id1, id2], e.header("cc", id2).header("cc"))  # access via .header
        self.assertEqual(e.cc(), [id1, id2])
        self.assertIs(e.header("cc", replace=True), e)
        self.assertEqual(e.cc(), [])
        self.assertIs(e.header("cc", id3), e)
        self.assertEqual(e.header("cc"),
                         [id3])  # cc and bcc headers always return list as documented (which is maybe not ideal)

    def test_date(self):
        """ Automatic adding of the Date header can be disabled. """
        self.assertIn(f"Date: ", str(Envelope(MESSAGE)))
        self.assertNotIn(f"Date: ", str(Envelope(MESSAGE).date(False)))

    def test_email_addresses(self):
        e = (Envelope()
             .cc("person1@example.com")
             .to("person2@example.com")  # add as string
             .to(["person3@example.com", "person4@example.com"])  # add as list
             .to("person5@example.com")
             .to("Duplicated <person5@example.com>")  # duplicated person should be ignored without any warning
             # we can delimit both by comma (standard) and semicolon (invalid but usual)
             .to(["person4@example.com; Sixth <person6@example.com>, Seventh <person7@example.com>"])
             # even invalid delimiting works
             .to(["person8@example.com,  , ; Ninth <person9@example.com>, Seventh <person7@example.com>"])
             .to("Named person 1 again <person1@example.com>")  # appeared twice –> will be discarded
             .bcc("person10@example.com")
             )

        self.assertEqual(9, len(e.to()))
        self.assertEqual(1, len(e.cc()))
        self.assertEqual(10, len(e.recipients()))
        self.assertEqual(str, type(",".join(e.to())))  # we can join elements as strings
        self.assertIn("Sixth <person6@example.com>", e.to())  # we can compare look up specific recipient

    def test_invalid_email_addresses(self):
        """ If we discard silently every invalid e-mail address received,
         the user would not know their recipients are not valid. """

        if sys.version_info < (3, 11):
            return

        e=(Envelope().to('person1@example.com, [invalid!email], person2@example.com'))
        self.assertEqual(3, len(e.to()))
        self.assertFalse(e.check(check_mx=False, check_smtp=False))

        e = (Envelope().to('person1@example.com, person2@example.com'))
        self.assertTrue(e.check(check_mx=False, check_smtp=False))

class TestSupportive(TestAbstract):
    def test_copy(self):
        factory = Envelope().cc("original@example.com").copy
        e1 = factory().to("independent-1@example.com")
        e2 = factory().to("independent-2@example.com").cc("additional@example.com")

        self.assertEqual(e1.recipients(), {'independent-1@example.com', 'original@example.com'})
        self.assertEqual(e2.recipients(),
                         {'independent-2@example.com', 'original@example.com', 'additional@example.com'})

    def test_message(self):
        e = Envelope("hello").as_message()
        self.assertEqual(type(e), EmailMessage)
        self.assertEqual(e.get_payload(), "hello\n")

    def test_smtp_quit(self):
        """ Calling .smtp_quit() on an object closes only its current SMTP connection,
            calling on the class closes them all."""
        if (sys.version_info.major, sys.version_info.minor) < (3, 7):
            # In Python3.6, sorting of dict seemed not to be stable for the case of SMTP.key.
            # The frozen dict of SMTP.key had parameters sorted differently than here in key(name),
            # hence the test failed. Since Python3.6 is after the end of life, I ignore.
            return

        class DummySMTPConnection:
            def __init__(self, name):
                self.name = name

            def quit(self):
                print(self.name)

        def key(name):
            return "{'host': '" + name + "', 'port': 25, 'user': None, 'password': None," \
                                         " 'security': None, 'timeout': 3, 'attempts': 3, 'delay': 3, 'local_hostname': None}"

        SMTPHandler._instances = {key(name): DummySMTPConnection(name) for name in (f"dummy{i}" for i in range(4))}

        e1 = Envelope().smtp("dummy1").smtp("dummy2")  # this object uses dummy2 only
        e2 = Envelope().smtp("dummy3")  # this object uses dummy3

        stdout = StringIO()
        with redirect_stdout(stdout):
            e2.smtp_quit()
            Envelope.smtp_quit()
            e1.smtp_quit()
            Envelope.smtp_quit()
        self.assertEqual("\n".join([f"dummy{i}" for i in [3, 0, 1, 2, 3, 2, 0, 1, 2, 3]]), stdout.getvalue().rstrip())


class TestBash(TestAbstract):

    def test_bcc(self):
        self.assertIn("Bcc: person@example.com", self.bash("--bcc", "person@example.com", "--preview"))
        self.assertNotIn("person@example.com", self.bash("--bcc", "person@example.com", "--send", "off"))

    def test_attachment(self):
        preview_text = f"Attachment generic.txt (text/plain): Small sample text at..."
        self.assertIn(preview_text, self.bash("--attach", self.text_attachment, "--preview"))
        o = self.bash("--attach", self.text_attachment, "--send", "0")
        self.assertNotIn(preview_text, o)
        self.assertIn('Content-Disposition: attachment; filename="generic.txt"', o)

    def test_subject(self):
        subject1 = "Hello world"
        subject2 = "Good bye sun"
        default_placeholder = "Encrypted message"  # default text used by the library

        def get_encrypted(subject, subject_encrypted):
            ref = self.bash("--attach", self.text_attachment, "--send", "0",
                            "--gpg", GNUPG_HOME,
                            "--to", IDENTITY_2,
                            "--from", IDENTITY_1,
                            "--encrypt",
                            "--subject", subject,
                            "--subject-encrypted", subject_encrypted, piped="text")
            # remove text "Have not been sent ... Encrypted subject: ..." prepended by ._send_now
            ref = ref[ref.index("\n\n") + 2:]
            return ref, Envelope.load(ref).as_message().as_string()

        encrypted, decrypted = get_encrypted(subject1, subject2)
        self.assertIn(f"Subject: {subject2}", encrypted)
        self.assertNotIn(subject1, encrypted)
        self.assertIn(f"Subject: {subject1}", decrypted)
        self.assertNotIn(subject2, decrypted)

        for x in ("False", "FALSE", "0", "oFF"):
            encrypted, decrypted = get_encrypted(subject1, x)
            self.assertIn(f"Subject: {subject1}", encrypted)
            self.assertIn(f"Subject: {subject1}", decrypted)

        for x in ("True", "TRUE", "1", "oN"):
            encrypted, decrypted = get_encrypted(subject1, x)
            self.assertIn(f"Subject: {default_placeholder}", encrypted)
            self.assertIn(f"Subject: {subject1}", decrypted)


class TestAttachment(TestAbstract):

    def test_casting(self):
        e = Envelope() \
            .attach("hello", "text/plain") \
            .attach(b"hello bytes")

        # attachment data are fetched as bytes by default
        self.assertEqual(b"hello", e.attachments()[0].data, bytes(e.attachments()[0]))

        # attachment can be casted to string (default UTF-8 encoding)
        self.assertEqual("hello", str(e.attachments()[0]))

        # the same is valid if the input has already been in bytes
        self.assertEqual(b"hello bytes", e.attachments()[1].data, bytes(e.attachments()[1]))
        self.assertEqual("hello bytes", str(e.attachments()[1]))

    def test_different_order(self):
        path = Path(self.text_attachment)
        e = Envelope() \
            .attach(path, "text/csv", "foo") \
            .attach(mimetype="text/csv", name="foo", path=self.text_attachment) \
            .attach(path, "foo", "text/csv") \
            .attach([(path, "text/csv", "foo",)]) \
            .attach(((path, "text/csv", "foo",),))
        model = repr(e.attachments()[0])
        # a tuple with a single attachment (and its details)
        e2 = Envelope(attachments=(path, "text/csv", "foo"))
        # a list that contains multiple attachments
        e3 = Envelope(attachments=[(path, "text/csv", "foo"), (path, "text/csv", "foo")])
        [self.assertEqual(model, repr(a)) for a in e.attachments() + e2.attachments() + e3.attachments()]

    def test_inline(self):
        def e():
            return Envelope().subject("Inline image message")

        image = self.image_file
        image_path = image.absolute()
        name = image.name

        # Specified the only HTML alternative, no plain text
        e1 = e().message(f"Hi <img src='cid:{name}'/>", alternative=HTML).attach(image, inline=True)
        single_alternative = ("Content-Type: multipart/related;",
                              "Subject: Inline image message",
                              'Content-Type: text/html; charset="utf-8"')
        img_msg = "Content-Disposition: inline", "R0lGODlhAwADAKEDAAIJAvz9/v///wAAACH+EUNyZWF0ZWQgd2l0aCBHSU1QACwAAAAAAwADAAAC"
        image_gif = "Hi <img src='cid:image.gif'/>", "Content-Type: image/gif", "Content-ID: <image.gif>", *img_msg
        multiple_alternatives = ('Content-Type: text/plain; charset="utf-8"',
                                 "Plain alternative",
                                 "Content-Type: multipart/related;",
                                 'Content-Type: text/html; charset="utf-8"')
        compare_lines = *single_alternative, *image_gif
        self.check_lines(e1, compare_lines)

        # Not specifying the only HTML alternative
        e2 = e().message(f"Hi <img src='cid:{name}'/>").attach(path=image_path, inline=True)
        self.check_lines(e2, compare_lines)

        # Two message alternatives, the plain is specified
        e3 = e().message(f"Hi <img src='cid:{name}'/>").message("Plain alternative", alternative=PLAIN,
                                                                boundary="bound") \
            .attach(image, inline=True)
        self.check_lines(e3, (
            'Content-Type: multipart/alternative; boundary="bound"',
            "Subject: Inline image message",
            "--bound",
            *multiple_alternatives,
            *image_gif))

        # Two message alternatives, the HTML is specified
        e4 = e().message(f"Hi <img src='cid:{name}'/>", alternative=HTML).message("Plain alternative") \
            .attach(path=image.absolute(), inline=True)
        self.check_lines(e4, ("Content-Type: multipart/alternative;",
                              "Subject: Inline image message",
                              *multiple_alternatives,
                              *image_gif))

        # Setting a name of an inline image
        custom_cid = "custom-name.jpg"
        e5 = e().message(f"Hi <img src='cid:{custom_cid}'/>").attach(path=image_path, inline=custom_cid)
        self.check_lines(e5,
                         (*single_alternative,
                          "Hi <img src='cid:custom-name.jpg'/>",
                          "Content-Type: image/gif",
                          "Content-ID: <custom-name.jpg>",
                          *img_msg))

        # Getting a name from the file name when contents is given
        custom_filename = "filename.gif"
        e6 = e().message(f"Hi <img src='cid:{custom_filename}'/>") \
            .attach(image.read_bytes(), name=custom_filename, inline=True)
        self.check_lines(e6,
                         (*single_alternative,
                          "Hi <img src='cid:filename.gif'/>",
                          "Content-Type: image/gif",
                          "Content-ID: <filename.gif>",
                          *img_msg))

        # Getting a name from the file name when contents is given
        # Setting a name of an inline image
        custom_filename = "filename.jpg"
        e7 = e().message(f"Hi <img src='cid:{custom_cid}'/>") \
            .attach(image.read_bytes(), name=custom_filename, inline=custom_cid)
        self.check_lines(e7,
                         (*single_alternative,
                          "Hi <img src='cid:custom-name.jpg'/>",
                          "Content-Type: image/gif",
                          "Content-ID: <custom-name.jpg>",
                          *img_msg))


class TestLoad(TestBash):
    inline_image = "tests/eml/inline_image.eml"

    def test_load(self):
        self.assertEqual(Envelope.load("Subject: testing message").subject(), "testing message")

    def test_load_file(self):
        e = Envelope.load(self.eml.read_text())
        self.assertEqual(e.subject(), "Hello world subject")

        # multiple headers returned as list and in the same order
        self.assertEqual(len(e.header("Received")), 2)
        self.assertEqual(e.header("Received")[1][:26], "from receiver2.example.com")

    def test_encoded_headers(self):
        e = Envelope.load(path=str(self.utf_header))
        self.assertEqual(e.subject(), "Re: text")
        self.assertEqual("Jiří <jiri@example.com>", e.from_())

        # Test header case-sensitive parsing in .header().
        #
        # (policy.header_store_parse is used no more but I leave the following comment since it is interesting)
        # We have to type the value to `str` due to this strange fact:
        # `key = "subject"; email["Subject"] = policy.header_store_parse(key, "hello")[1];`
        #   would force `str(email)` output 'subject: hello' (small 's'!)
        # Interestingly, setting `key = "anything else";` would output correct 'Subject: hello'
        # val = str(policy.header_store_parse(k, val)[1])
        self.assertIn("Subject: Re: text", str(e))

        # When longer than certain number of characters, the method Parser.parse header.Header.encode()
        # returned chunks that were problematic to parse with policy.header_store_parse.
        # This will be treated as 'unknown-8bit' header.
        address = Envelope.load("To: Novák Honza Name longer than 75 chars <honza.novak@example.com>").to()[0]
        self.assertEqual("honza.novak@example.com", address.address)
        self.assertEqual("Novák Honza Name longer than 75 chars", address.name)

        # other than UTF-8 headers
        iso_2 = "Subject: =?iso-8859-2?Q?=BE=E1dost_o_blokaci_dom=E9ny?="
        self.assertEqual("žádost o blokaci domény", Envelope.load(iso_2).subject())

    def test_load_bash(self):
        self.assertIn("Hello world subject", self.bash())

    def test_bash_display(self):
        self.assertEqual("Hello world subject", self.bash("--subject"))

    def test_multiline_folded_header(self):
        self.assertEqual(
            "Very long text Very long text Very long text Very long text Ver Very long text Very long text",
            self.bash("--subject", file=self.quopri))

    def test_alternative_and_related(self):
        e = Envelope.load(path=self.inline_image)
        self.assertEqual("Hi <img src='cid:image.gif'/>", e.message())
        self.assertEqual("Inline image message", e.subject())
        self.assertEqual("Plain alternative", e.message(alternative=PLAIN))
        self.assertEqual(self.image_file.read_bytes(), bytes(e.attachments()[0]))

    def test_accessing_attachments(self):
        # correctly preview the attachments
        self.assertEqual("image.gif (image/gif): <img src='cid:True'/>",
                         self.bash("--attachments", file=Path(self.inline_image)))

        # correctly access the attachment, the bytes kept intact
        self.assertEqual(self.image_file.read_bytes(),
                         self.bash("--attachments", "image.gif", file=Path(self.inline_image), decode=False))

    def test_another_charset(self):
        self.assertEqual("Dobrý den", Envelope.load(self.charset).message())

    def test_internationalized(self):
        self.assertEqual("Žluťoučký kůň", Envelope.load(self.internationalized).subject())

        # when using preview, we do not want to end up with "Subject: =?utf-8?b?xb1sdcWlb3XEjWvDvSBrxa/FiA==?="
        # which could appear even when .subject() shows decoded version
        self.assertIn("Subject: Žluťoučký kůň", Envelope.load(self.internationalized).preview().splitlines())

    def test_group_recipient(self):
        # msg = "WARNING:envelope.envelope:E-mail address cannot be parsed: ['undisclosed-recipients:;'] at header To"
        # with self.assertLogs('envelope', level='WARNING') as cm:
        #     e = Envelope.load(self.group_recipient)
        # self.assertEqual(cm.output, [msg])
        e = Envelope.load(self.group_recipient)

        self.assertEqual([], e.to())
        self.assertEqual("From Alice Smith", e.subject())

        self.assertEqual({"hi", "hi2"}, Envelope.load("To: group: hi; group b: hi2;").recipients())

    def test_invalid_characters(self):
        msg = "WARNING:envelope.parser:Replacing some invalid characters in text/plain:" \
            " 'utf-8' codec can't decode byte 0xe1 in position 1: invalid continuation byte"
        with self.assertLogs('envelope', level='WARNING') as cm:
            e = Envelope.load(self.invalid_characters)
        self.assertEqual(cm.output, [msg])

        text = 'V�\x17Een� z�kazn�ku!\n Va\x161e z�silka bude'
        self.assertEqual(text, e.message(alternative="plain")[:len(text)])
        html = '<HTML><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><BODY><P>Vážený'
        self.assertEqual(html, e.message()[:len(html)])

        # test subject decoded from base64
        subject = "Vaše zásilka ceká na dorucení"
        self.assertEqual(subject, e.subject())

        # test header internationalized
        self.assertEqual(subject, e.header("Subject"))
        self.assertEqual(subject, e.header("subJEct"))
        self.assertEqual("Thu", e.header("dATe")[:3])

    def test_invalid_headers(self):
        """ Following file has some invalid headers whose parsing would normally fail. """
        msg = ['WARNING:envelope.envelope:Header List-Unsubscribe could not be successfully '
               "loaded with <mailto:RB��R@innovabrokers.com.co>: 'Header' object is not subscriptable",
               'WARNING:envelope.parser:Replacing some invalid characters in text/html: '
               'unknown encoding: "utf-8message-id: <123456@example.com>']
        with self.assertLogs('envelope', level='WARNING') as cm:
            e = Envelope.load(self.invalid_headers)
        if (3, 6) == (sys.version_info.major, sys.version_info.minor):  # XX drop with Python3.6 support
            self.assertIn("support indexing", cm.output[0])
        else:
            self.assertEqual(msg, cm.output)

        self.assertEqual("An invalid header", e.message())
        self.assertEqual("Support Team <no_reply-2345@example.com>", e.from_())


class TestTransfer(TestBash):
    long_text = "J'interdis aux marchands de vanter trop leurs marchandises." \
        " Car ils se font vite pédagogues et t'enseignent comme but ce qui n'est par essence qu'un moyen," \
        " et te trompant ainsi sur la route à suivre les voilà bientôt qui te dégradent," \
                " car si leur musique est vulgaire ils te fabriquent pour te la vendre une âme vulgaire."
    quoted = "J'interdis aux marchands de vanter trop leurs marchandises. Car ils se font v=" \
        "\nite p=C3=A9dagogues et t'enseignent comme but ce qui n'est par essence qu'un =" \
        "\nmoyen, et te trompant ainsi sur la route =C3=A0 suivre les voil=C3=A0 bient=" \
             "\n=C3=B4t qui te d=C3=A9gradent, car si leur musique est vulgaire ils te fabriq=" \
             "\nuent pour te la vendre une =C3=A2me vulgaire."

    def _quoted_message(self, e: Envelope):
        self.assertEqual(self.long_text, e.message())
        self.assertIn(self.long_text, e.preview())  # when using preview, we receive original text
        output = str(e.send(False))  # but when sending, quoted text is got instead
        self.assertNotIn(self.long_text, output)
        self.assertIn(self.quoted, output)

    def test_auto_quoted_printable(self):
        """ Envelope internally converts long lines to quoted-printable. """
        self._quoted_message(Envelope().message(self.long_text))

    def test_quoted_printable(self):
        """ Envelope is able to load the text that is already quoted. """
        self._quoted_message(Envelope.load(f"Content-Transfer-Encoding: quoted-printable\n\n{self.quoted}"))

    def test_quoted_printable_bash(self):
        """ Envelope is able to load the text that is already quoted in a file.
            As long_text contains non-ASCII characters, it tests the program locale also.
            In Python3.6, the locale LC_ALL=C fails. """
        self.assertEqual(self.long_text, self.bash("--message", file=self.quopri))

    def test_base64(self):
        hello = "aGVsbG8gd29ybGQ="
        self.assertEqual(Envelope.load(f"\n{hello}").message(), hello)
        self.assertEqual(Envelope.load(f"Content-Transfer-Encoding: base64\n\n{hello}").message(), "hello world")

    def test_implanted_transfer(self):
        e = (Envelope().header("Content-Transfer-Encoding", "quoted-printable").message(self.quoted))
        self.assertEqual(self.long_text, e.message())

        # we replace Content-Transfer-Encoding and change the message
        original = "hello world"
        hello = "aGVsbG8gd29ybGQ="
        e = (Envelope().header("Content-Transfer-Encoding", "base64").message(hello))
        self.assertEqual(original, e.message())

        # the user specified Content-Transfer-Encoding but left the message unencoded
        e2 = (Envelope().header("Content-Transfer-Encoding", "base64").message(original))
        self.assertEqual(original, e2.message())


class TestSMTP(TestAbstract):
    def test_smtp_parameters(self):
        self.assertSubset(Envelope().smtp()._smtp.__dict__,
                          {"host": "localhost", "port": 25, "timeout": 3, "attempts": 3, "delay": 3})
        self.assertSubset(Envelope().smtp(port=32)._smtp.__dict__,
                          {"host": "localhost", "port": 32})
        self.assertSubset(Envelope().smtp(timeout=5)._smtp.__dict__, {"timeout": 5})
        self.assertSubset(Envelope().smtp("tests/smtp-configuration.ini")._smtp.__dict__,
                          {"timeout": 3, "user": "envelope-example-identity@example.com", "password": "", "port": 123})


class TestReport(TestAbstract):
    xarf = Path("tests/eml/multipart-report-xarf.eml")

    def test_loading_xarf(self):
        # no report in an empty object
        self.assertFalse(Envelope()._report())

        # expected XARF report
        e = Envelope.load(self.xarf)
        report = e._report()
        self.assertSubset(report["ReporterInfo"], {"ReporterOrg": 'Example'})
        self.assertSubset(report["Report"], {'SourceIp': '192.0.2.1'})

    def test_unsupported_message(self):
        # only `Content-Type: message/feedback-report` is implemented within `multipart/report``
        t = self.xarf.read_text().replace("Content-Type: message/feedback-report",
                                          "Content-Type: message/UNSUPPORTED")
        msg = "WARNING:envelope.envelope:Message might not have been loaded correctly. " \
            "Parsing multipart/report / message/unsupported not implemented."
        with self.assertLogs('envelope', level='WARNING') as cm:
            Envelope.load(t)
        self.assertEqual(cm.output, [msg])

        # `Content-Type: message` is not implemented within `multipart/mixed`
        msg = "WARNING:envelope.envelope:Message might not have been loaded correctly. "\
            "Parsing multipart/mixed / message/feedback-report failed or not implemented."
        t = self.xarf.read_text().replace("Content-Type: multipart/report",
                                          "Content-Type: multipart/mixed")
        with self.assertLogs('envelope', level='WARNING') as cm:
            Envelope.load(t)
        self.assertEqual(cm.output, [msg])


if __name__ == '__main__':
    main()
