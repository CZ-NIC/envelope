import logging
import sys
import unittest
from pathlib import Path
from typing import Tuple, Union

from envelope import envelope

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


class TestAbstract(unittest.TestCase):
    def _check_lines(self, o, lines: Union[str, Tuple[str, ...]], longer=None, print_=False):
        """ Converts Envelope objects to str and asserts that lines are present. """
        if type(lines) is str:
            lines = lines,
        output = str(o).splitlines()
        if print_:
            print(o)
        for line in lines:
            self.assertIn(line, output)
        if longer:
            self.assertGreater(len(output), longer)


class TestEnvelope(TestAbstract):
    def test_message_generating(self):
        self._check_lines(envelope("dumb message")
                          .subject("my subject")
                          .send(False),
                          ("Subject: my subject",
                           "dumb message",), 10)


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
        self._check_lines(envelope("dumb message")
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
        self._check_lines(envelope("dumb message")
                          .smime()
                          .signature(Path("tests/smime/key-cert-together.pem"))
                          .sign(),
                          ('Content-Disposition: attachment; filename="smime.p7s"',
                           "MIIEggYJKoZIhvcNAQcCoIIEczCCBG8CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"))

    def test_smime_key_cert_together_passphrase(self):
        self._check_lines(envelope("dumb message")
                          .smime()
                          .signature(Path("tests/smime/key-cert-together-passphrase.pem"), passphrase="test")
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
        self._check_lines(envelope("dumb message")
                          .smime()
                          .reply_to("test-reply@example.com")
                          .subject("my message")
                          .encryption(Path("tests/smime/cert.pem"))
                          .send(False),
                          ('Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
                           "Z2l0cyBQdHkgTHRkAhROmwkIH63oarp3NpQqFoKTy1Q3tTANBgkqhkiG9w0BAQEF",
                           "Subject: my message",
                           "Reply-To: test-reply@example.com"), 10)

        # XX decrypt test https://m2crypto.readthedocs.io/en/latest/howto.smime.html#decrypt


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

        self._check_lines(envelope("dumb message")
                          .gpg("tests/gpg_ring/")
                          .sign(),
                          ('dumb message',
                           '-----BEGIN PGP SIGNATURE-----',
                           '-----END PGP SIGNATURE-----',), 10)

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

        self._check_lines(envelope("dumb message")
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

        self._check_lines(envelope("dumb message")
                          .to("envelope-example-identity-2@example.com")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .subject("dumb subject")
                          .encryption()
                          .send(False),
                          ("Encrypted message: b'dumb message'",
                           "Encrypted subject: dumb subject",
                           "Subject: Encrypted message",
                           "To: envelope-example-identity-2@example.com",
                           "From: envelope-example-identity@example.com",
                           'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";'
                           ), 10)

    def test_gpg_sign_passphrase(self):
        self._check_lines(envelope("dumb message")
                          .to("envelope-example-identity-2@example.com")
                          .gpg("tests/gpg_ring/")
                          .from_("envelope-example-identity@example.com")
                          .signature("3C8124A8245618D286CF871E94CE2905DB00CDB7", "test"),  # passphrase needed
                          ("-----BEGIN PGP SIGNATURE-----",), 10)


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
        self._check_lines(envelope().message(self.plain).mime("plain", "auto"), pl)
        self._check_lines(envelope().message(self.plain), pl)
        self._check_lines(envelope().message(self.html).mime("plain"), pl)

    def test_html(self):
        m = self.mime_html
        self._check_lines(envelope().message(self.plain).mime("html", "auto"), m)
        self._check_lines(envelope().message(self.html), m)
        self._check_lines(envelope().message(self.html_without_line_break), m)

    def test_nl2br(self):
        nobr = "Second"
        br = "Second<br>"
        self._check_lines(envelope().message(self.html), nobr)  # there already is a <br> tag so nl2br "auto" should not convert it
        self._check_lines(envelope().message(self.html).mime(nl2br=True), br)

        self._check_lines(envelope().message(self.html_without_line_break), br)
        self._check_lines(envelope().message(self.html_without_line_break).mime("plain", True), nobr)  # nl2br disabled in "plain"
        self._check_lines(envelope().message(self.html_without_line_break).mime(nl2br=False), nobr)



if __name__ == '__main__':
    unittest.main()
