import logging
import sys
import unittest
from pathlib import Path
from subprocess import PIPE, STDOUT, Popen
from tempfile import TemporaryDirectory
from typing import Tuple, Union

from envelope import Envelope

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

GPG_PASSPHRASE = "test"
GPG_IDENTITY_1_FINGERPRINT = "F14F2E8097E0CCDE93C4E871F4A4F26779FA03BB"


class TestAbstract(unittest.TestCase):
    def _check_lines(self, o, lines: Union[str, Tuple[str, ...]] = (), longer: Union[int, Tuple[int, int]] = None,
                     print_=False, not_in: Union[str, Tuple[str, ...]] = (), raises=(), result=None):
        """ Converts Envelope objects to str and asserts that lines are present.
        :type lines: Assert in.
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

        if print_:
            print(o)
        for line in lines:
            self.assertIn(line, output)
        for line in not_in:
            self.assertNotIn(line, output)

        # result state
        if result is not None:
            self.assertIs(bool(o), result)

        # result line count range
        if type(longer) is tuple:
            longer, shorter = longer
            self.assertLess(len(output), shorter)
        if longer:
            self.assertGreater(len(output), longer)


class TestEnvelope(TestAbstract):
    def test_message_generating(self):
        self._check_lines(Envelope("dumb message")
                          .subject("my subject")
                          .send(False),
                          ("Subject: my subject",
                           "dumb message",), 10)

    def test_1000_split(self):
        self._check_lines(Envelope().message("short text").subject("my subject").send(False),
                          ("Subject: my subject",
                           'Content-Transfer-Encoding: 7bit',
                           "short text"), 10)

        # this should be no more 7bit but base64 (or quoted-printable which is however not guaranteed)
        e = Envelope().message("Longer than thousand chars. " * 1000).subject("my subject").send(False)
        self._check_lines(e,
                          ("Subject: my subject",), 100,
                          not_in=('Content-Transfer-Encoding: 7bit',)
                          )
        self.assertFalse(any(line for line in str(e).splitlines() if len(line) > 999))


class TestSmime(TestAbstract):
    # create a key and its certificate valid for 100 years
    # openssl req -newkey rsa:1024 -nodes -x509 -days 36500 -out certificate.pem

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
        self._check_lines(Envelope("dumb message")
                          .smime()
                          .subject("my subject")
                          .reply_to("test-reply@example.com")
                          .signature(Path("tests/smime/key.pem"), cert=Path("tests/smime/cert.pem"))
                          .send(False),
                          ('Content-Disposition: attachment; filename="smime.p7s"',
                           "MIIEggYJKoZIhvcNAQcCoIIEczCCBG8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3",
                           "dumb message",
                           "Subject: my subject",
                           "Reply-To: test-reply@example.com"), 10)

    def test_smime_key_cert_together(self):
        self._check_lines(Envelope("dumb message")
                          .smime()
                          .signature(Path("tests/smime/key-cert-together.pem"))
                          .sign(),
                          ('Content-Disposition: attachment; filename="smime.p7s"',
                           "MIIEggYJKoZIhvcNAQcCoIIEczCCBG8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"))

    def test_smime_key_cert_together_passphrase(self):
        self._check_lines(Envelope("dumb message")
                          .smime()
                          .signature(Path("tests/smime/key-cert-together-passphrase.pem"), passphrase=GPG_PASSPHRASE)
                          .sign(),
                          ('Content-Disposition: attachment; filename="smime.p7s"',
                           "MIIEggYJKoZIhvcNAQcCoIIEczCCBG8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"), 10)

    def test_smime_encrypt(self):
        # Message will look that way:
        # MIME-Version: 1.0
        # Content-Disposition: attachment; filename="smime.p7m"
        # Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
        # Content-Transfer-Encoding: base64
        #
        # MIIBPQYJKoZIhvcNAQcDoIIBLjCCASoCAQAxgfcwgfQCAQAwXTBFMQswCQYDVQQG
        # EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk
        # Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF
        # AASBgHriGJfbxNVpzDhxnObA6q0xoAuXOgYobG5HxpGi9InmlYoWS6ZkeDTMo70B
        # nnXprxG2Q+/0GHJw48R1/B2d4Ln1sYJe5BXl3LVr7QWpwPb+62AZ1TN8793jSic6
        # jBl/v6gDTRoEEjnb8RAkyvDJ7d6OOokgFOfCfTAUOBoZhZrqMCsGCSqGSIb3DQEH
        # ATAUBggqhkiG9w0DBwQIt4seJLnZZW+ACBRKsu4Go7lm
        self._check_lines(Envelope("dumb message")
                          .smime()
                          .reply_to("test-reply@example.com")
                          .subject("my message")
                          .encryption(Path("tests/smime/cert.pem"))
                          .send(False),
                          ('Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
                           "Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF",
                           "Subject: my message",
                           "Reply-To: test-reply@example.com"), 10)

    def test_multiple_recipients(self):
        from M2Crypto import SMIME, BIO
        msg = "dumb message"

        def is_decryptable(key, cert, text):
            # Load private key and cert and decrypt
            s = SMIME.SMIME()
            s.load_key(key, cert)
            p7, data = SMIME.smime_load_pkcs7_bio(BIO.MemoryBuffer(bytes(text)))
            try:
                return s.decrypt(p7) == bytes(msg, "utf-8")
            except SMIME.PKCS7_Error:
                return False

        # encrypt for both keys
        output = (Envelope(msg)
                  .smime()
                  .reply_to("test-reply@example.com")
                  .subject("my message")
                  .encrypt([Path("tests/smime/cert.pem"), Path("tests/smime/smime-identity@example.com-cert.pem")]))

        self.assertTrue(is_decryptable('tests/smime/smime-identity@example.com-key.pem',
                                       'tests/smime/smime-identity@example.com-cert.pem',
                                       output))
        self.assertTrue(is_decryptable('tests/smime/key.pem', 'tests/smime/cert.pem',
                                       output))

        # encrypt for single key only
        output = (Envelope(msg)
                  .smime()
                  .reply_to("test-reply@example.com")
                  .subject("my message")
                  .encrypt([Path("tests/smime/cert.pem")]))

        self.assertFalse(is_decryptable('tests/smime/smime-identity@example.com-key.pem',
                                        'tests/smime/smime-identity@example.com-cert.pem',
                                        output))
        self.assertTrue(is_decryptable('tests/smime/key.pem', 'tests/smime/cert.pem',
                                       output))


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

        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .sign(),
                          ('dumb message',
                           '-----BEGIN PGP SIGNATURE-----',
                           '-----END PGP SIGNATURE-----',), 10)

    def test_gpg_auto_sign(self):
        # mail from "envelope-example-identity@example.com" is in ring
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .sign("auto"),
                          ('dumb message',
                           '-----BEGIN PGP SIGNATURE-----',
                           '-----END PGP SIGNATURE-----',), 10)

        # mail from "envelope-example-identity-not-stated-in-ring@example.com" should not be signed
        output = str(Envelope("dumb message")
                     .gpg("tests/gpg_ring/")
                     .from_("envelope-example-identity-not-stated-in-ring@example.com")
                     .sign("auto")).splitlines()
        self.assertNotIn('-----BEGIN PGP SIGNATURE-----', output)

        # force-signing without specifying a key nor sending address shuold produce a message signed with a first-found key
        output = str(Envelope("dumb message")
                     .gpg("tests/gpg_ring/")
                     .sign(True)).splitlines()
        self.assertIn('-----BEGIN PGP SIGNATURE-----', output)

        # force-signing without specifying a key and with sending from an e-mail which is not in the keyring must fail
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
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

        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-example-identity-2@example.com")
                          .encrypt(),
                          ("-----BEGIN PGP MESSAGE-----",), 10)

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

        self._check_lines(Envelope("dumb message")
                          .to("envelope-example-identity-2@example.com")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .subject("dumb subject")
                          .encryption()
                          .send(False),
                          ("Encrypted message: dumb message",
                           "Encrypted subject: dumb subject",
                           "Subject: Encrypted message",
                           "To: envelope-example-identity-2@example.com",
                           "From: envelope-example-identity@example.com",
                           'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";'
                           ), 10)

    def test_gpg_auto_encrypt(self):
        # mail `from` "envelope-example-identity@example.com" is in ring
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-example-identity@example.com")
                          .encrypt("auto"),
                          ('-----BEGIN PGP MESSAGE-----',
                           '-----END PGP MESSAGE-----',), (10, 15), not_in="dumb message")

        # mail `to` "envelope-unknown@example.com" unknown, must be both signed and encrypted
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-example-identity-2@example.com")
                          .signature("auto")
                          .encrypt("auto"),
                          ('-----BEGIN PGP MESSAGE-----',
                           '-----END PGP MESSAGE-----',), 20, not_in="dumb message")

        # mail `from` "envelope-unknown@example.com" unknown, must not be encrypted
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-unknown@example.com")
                          .to("envelope-example-identity@example.com")
                          .encrypt("auto"),
                          ('dumb message',), (0, 2), not_in='-----BEGIN PGP MESSAGE-----')

        # mail `to` "envelope-unknown@example.com" unknown, must not be encrypted
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-unknown@example.com")
                          .encrypt("auto"),
                          ('dumb message',), (0, 2), not_in='-----BEGIN PGP MESSAGE-----')

        # force-encrypting without having key must return empty response
        self._check_lines(Envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-unknown@example.com")
                          .encryption(True), longer=(0, 1), result=False)

    def test_gpg_sign_passphrase(self):
        self._check_lines(Envelope("dumb message")
                          .to("envelope-example-identity-2@example.com")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .signature("3C8124A8245618D286CF871E94CE2905DB00CDB7", GPG_PASSPHRASE),  # passphrase needed
                          ("-----BEGIN PGP SIGNATURE-----",), 10)

    def test_auto_import(self):
        temp = TemporaryDirectory()

        # no signature - empty ring
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .signature(),
                          raises=RuntimeError)

        # import key to the ring
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .sign(Path("tests/gpg_keys/envelope-example-identity@example.com.key")),
                          ('dumb message',
                           '-----BEGIN PGP SIGNATURE-----',
                           '-----END PGP SIGNATURE-----',), 10)

        # key in the ring from last time
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .signature(),
                          ('dumb message',
                           '-----BEGIN PGP SIGNATURE-----',
                           '-----END PGP SIGNATURE-----',), 10)

        # cannot encrypt for identity-2
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-example-identity-2@example.com")
                          .encryption(),
                          result=False)

        # signing should fail since we have not imported key for identity-2
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .from_("envelope-example-identity-2@example.com")
                          .signature(),
                          raises=RuntimeError)

        # however it should pass when we explicitly use an existing GPG key to be signed with
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .from_("envelope-example-identity-2@example.com")
                          .signature(GPG_IDENTITY_1_FINGERPRINT),
                          ('dumb message',
                           '-----BEGIN PGP SIGNATURE-----',
                           '-----END PGP SIGNATURE-----',), 10, result=True)

        # import encryption key - no passphrase needed while importing or using public key
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .from_("envelope-example-identity@example.com")
                          .to("envelope-example-identity-2@example.com")
                          .encryption(Path("tests/gpg_keys/envelope-example-identity-2@example.com.key")),
                          result=True)

        # signing with an invalid passphrase should fail for identity-2
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .from_("envelope-example-identity-2@example.com")
                          .signature(passphrase="INVALID PASSPHRASE"),
                          result=False)

        # signing with a valid passphrase should pass
        self._check_lines(Envelope("dumb message")
                          .gpg(temp.name)
                          .from_("envelope-example-identity-2@example.com")
                          .signature(passphrase=GPG_PASSPHRASE),
                          result=True)

        temp.cleanup()


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
        self._check_lines(Envelope().message(self.plain).mime("plain", "auto"), pl)
        self._check_lines(Envelope().message(self.plain), pl)
        self._check_lines(Envelope().message(self.html).mime("plain"), pl)

    def test_html(self):
        m = self.mime_html
        self._check_lines(Envelope().message(self.plain).mime("html", "auto"), m)
        self._check_lines(Envelope().message(self.html), m)
        self._check_lines(Envelope().message(self.html_without_line_break), m)

    def test_nl2br(self):
        nobr = "Second"
        br = "Second<br>"
        self._check_lines(Envelope().message(self.html), nobr)  # there already is a <br> tag so nl2br "auto" should not convert it
        self._check_lines(Envelope().message(self.html).mime(nl2br=True), br)

        self._check_lines(Envelope().message(self.html_without_line_break), br)
        self._check_lines(Envelope().message(self.html_without_line_break).mime("plain", True), nobr)  # nl2br disabled in "plain"
        self._check_lines(Envelope().message(self.html_without_line_break).mime(nl2br=False), nobr)


class TestFrom(TestAbstract):
    def test_from(self):
        id1 = "identity-1@example.com"
        id2 = "identity-2@example.com"
        self._check_lines(Envelope("dumb message").sender(id1),
                          f"From: {id1}", not_in=f"Sender: {id1}")
        self._check_lines(Envelope("dumb message", sender=id1),
                          f"From: {id1}", not_in=f"Sender: {id1}")

        self._check_lines(Envelope("dumb message", from_=id1),
                          f"From: {id1}", not_in=f"Sender: {id1}")
        self._check_lines(Envelope("dumb message").from_(id1),
                          f"From: {id1}", not_in=f"Sender: {id1}")

        self._check_lines(Envelope("dumb message")
                          .from_(id1)
                          .sender(id2),
                          (f"From: {id1}", f"Sender: {id2}"))
        self._check_lines(Envelope("dumb message")
                          .sender(id2)
                          .from_(id1),
                          (f"From: {id1}", f"Sender: {id2}"))


class TestSubject(TestAbstract):
    def test_cache_recreation(self):
        s1 = "Test"
        s2 = "Another"
        e = Envelope("dumb message").subject(s1)
        self._check_lines(e, f"Subject: {s1}")

        e.subject(s2)
        self._check_lines(e, f"Subject: {s2}")


class TestHeaders(TestAbstract):
    def test_generic_header_manipulation(self):
        # Add a custom header and delete it
        e = Envelope("dumb message").subject("my subject").header("custom", "1")
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
        e = Envelope("dumb message") \
            .subject(s) \
            .header("custom", "1") \
            .cc(id1)  # set headers via their specific methods
        self.assertEqual(e.header("subject"), s)  # access via .header
        self.assertEqual(e.subject(), s)  # access via specific method .subject
        self.assertIs(e.header("subject", replace=True), e)
        self.assertIs(e.header("subject"), None)
        self.assertEqual(e.header("subject", s).subject(), s)  # set via generic method

        self.assertEqual(e.header("cc", id2).header("cc"), [id1, id2])  # access via .header
        self.assertEqual(e.cc(), [id1, id2])
        self.assertIs(e.header("cc", replace=True), e)
        self.assertEqual(e.cc(), [])
        self.assertIs(e.header("cc", id3), e)
        self.assertEqual(e.header("cc"), [id3])  # cc and bcc headers always return list as documented (which is maybe not ideal)

    def test_date(self):
        """ Automatic adding of the Date header can be disabled. """
        self.assertIn(f"Date: ", str(Envelope("dumb message")))
        self.assertNotIn(f"Date: ", str(Envelope("dumb message").date(False)))


class TestSupportive(TestAbstract):
    def test_copy(self):
        factory = Envelope().cc("original@example.com").copy
        e1 = factory().to("independent-1@example.com")
        e2 = factory().to("independent-2@example.com").cc("additional@example.com")

        self.assertEqual(e1.recipients(), {'independent-1@example.com', 'original@example.com'})
        self.assertEqual(e2.recipients(), {'independent-2@example.com', 'original@example.com', 'additional@example.com'})


class TestDefault(TestAbstract):
    def test_default(self):
        self.assertEqual(Envelope().subject(), None)

        Envelope.default.subject("bar")
        self.assertEqual(Envelope().subject("foo").subject(), "foo")
        self.assertEqual(Envelope().subject(), "bar")


class TestLoad(TestAbstract):
    eml = Path("tests/eml/mail.eml")
    cmd = ["python3", "-m", "envelope"]

    def test_load(self):
        self.assertEqual(Envelope.load("Subject: testing message").subject(), "testing message")

    def test_load_file(self):
        e = Envelope.load(self.eml.read_text())
        self.assertEqual(e.subject(), "Hello world subject")

        # multiple headers returned as list and in the same order
        self.assertEqual(len(e.header("Received")), 2)
        self.assertEqual(e.header("Received")[1][:26], "from receiver2.example.com")

    def test_load_bash(self):
        p = Popen(self.cmd, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        output = p.communicate(input=self.eml.read_bytes())[0].decode()
        self.assertIn("Hello world subject", output)

    def test_bash_display(self):
        p = Popen(self.cmd + ["--subject"], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        output = p.communicate(input=self.eml.read_bytes())[0].decode()
        self.assertEqual("Hello world subject", output.strip())


if __name__ == '__main__':
    unittest.main()
