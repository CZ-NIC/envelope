"""Encryption methods of `Envelope`: the public `encryption`/`encrypt` plus GPG/S-MIME encryption helpers.
Also holds the S-MIME helpers that sign+encrypt together (`_smime_sign_encrypt`, `_encrypt_smime_now`).
Mixin: shares one `self` with `Envelope`; nothing here is meant to be used standalone.
"""
import logging
import re
from email.message import EmailMessage
from itertools import chain
from pathlib import Path
from typing import Union

from .utils import assure_list, assure_fetched

logger = logging.getLogger("envelope.envelope")  # same logger name as before the split


class _EncryptionMixin:
    def encryption(self, key=True, *, key_path=None):
        """
        Turn encrypting on.
        :param key:
            * GPG:
                * True (blank) for the user default keys (identities in the "from", "to", "cc" and "bcc" headers)
                * "auto" for turning on encrypting if there is a matching key for every recipient
                * key ID/fingerprint
                * e-mail address of the identity whose key is to be encrypted with
                * Any attainable contents with the key to be encrypted with (will be imported into keyring)
                * an iterable with the identities specified by key ID / fingerprint / e-mail address / raw key data
            * S/MIME any attainable contents with certificate to be encrypted with or more of them in an iterable
        :param key_path: Path to a file with the `key` or more of them in an iterable.
        """
        if key_path:
            key = [Path(k) for k in assure_list(key_path)]
        if key is True and self._encrypt not in [None, False]:
            # use case envelope().encrypt(key="keystring").send(encrypt=True) should still have key in self._encrypt
            # (and not just "True")
            pass
        elif key is not None:
            # possible types: True, AUTO, str, list of bytes
            # (the reason str type is not converted into bytes: we want the (str) constant AUTO to not be converted)
            self._encrypt = assure_fetched(key) if isinstance(key, (bool, str)) \
                else [assure_fetched(k, bytes) for k in assure_list(key)]
        return self

    def encrypt(self, key=True, sign=None, *, key_path=None):
        """
        Encrypt now.
        :param key:
            * GPG:
                * True (blank) for the user default keys (identities in the "from", "to", "cc" and "bcc" headers)
                * "auto" for turning on encrypting if there is a matching key for every recipient
                * key ID/fingerprint
                * e-mail address of the identity whose key is to be encrypted with
                * Any attainable contents with the key to be encrypted with (will be imported into keyring)
                * an iterable with the identities specified by key ID / fingerprint / e-mail address / raw key data
            * S/MIME any attainable contents with certificate to be encrypted with or their list
        :param sign: Turn signing on.
            The parameter will be passed as the `key` parameter of the .signature method.
            * GPG: Ex: True or default signing key ID/fingerprint.
            * S/MIME: Any attainable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use the full .signature() method instead.)
        :param key_path: Path to a file with the `key` or their list.
        """
        self._processed = True
        self.encryption(key=key, key_path=key_path)
        self._start(sign=sign)
        return self

    def _encrypt_gpg_now(self, message, encrypt, sign_fingerprint):
        exc = []
        if not any(chain(self._to, self._cc, self._bcc)):
            exc.append("No recipient e-mail specified")
        if self._from is None:
            exc.append("No From e-mail specified."
                       " If not planning to decipher later, put from_=False or --no-from flag.")
        if exc:
            raise RuntimeError("Encrypt key present. " + ", ".join(exc))
        # According to https://gnupg.readthedocs.io/en/latest/ , the recipients should contain fingerprints
        # but putting there e-mail addresses works.
        # However, we retype to str, since `encrypt` contains bytes (because it might have contained raw keys
        # which has been imported and replaced with the fingerprints).
        decipherers = [assure_fetched(x, str) for x in
                       (encrypt if isinstance(encrypt, list) else self._get_decipherers())]

        status = self._gnupg.encrypt(
            data=message,
            recipients=decipherers,
            sign=sign_fingerprint if sign_fingerprint else None,
            passphrase=self._passphrase if self._passphrase else None
        )
        # even though the status.ok = True,
        # if the sign key is not found and there exists a secret key in the ring, the latter is used
        # with `gpg: all values passed to '--default-key' ignored` (the same is valid for ._sign_gpg_now())
        if sign_fingerprint and not re.search(r'gpg: using "[^"]+" as default secret key for signing', status.stderr):
            logger.warning(f"The secret key for {sign_fingerprint} seems to not be used,"
                           f" check if it is in the keyring: {self._get_gnupg_home(True)}gpg --list-secret-keys")
            return False
        if status.ok:
            return status.data
        else:
            logger.warning(status.stderr)
            if "No secret key" in status.stderr:
                logger.warning(f"Secret key not found in {self._get_gnupg_home()} home folder. Create one.")
            if "Bad passphrase" in status.stderr:
                logger.warning(f"Bad passphrase for key.")
            if "Operation cancelled" in status.stderr:
                logger.info(f"You cancelled the key prompt.")
            if "Syntax error in URI" in status.stderr:
                logger.info(f"Unable to download missing key.")
            if any(s in status.stderr for s in ["No name", "No data", "General error",
                                                "Syntax error in URI", "No public key"]):
                missing = [x for x in decipherers if not bool(self._gnupg.list_keys(keys=x))]
                if missing:
                    logger.warning(f"Key for {', '.join(missing)} seems missing,"
                                   f" see: {self._get_gnupg_home(True)}gpg --list-keys")
            return False

    def _get_decipherers(self) -> set[str]:
        """
        :return: Set of e-mail addresses
        """
        return set(x.address for x in self._to + self._cc + self._bcc + [x for x in [self._from] if x])

    def _smime_sign_encrypt(self, email, sign, encrypt):
        load_pem_private_key, pkcs7, load_pem_x509_certificates, load_pem_x509_certificate, hashes, serialization = self._import_cryptoraphy_modules()

        if self._cert:
            sender_certs = self._cert
        else:
            # certificate is in sign (--sign_path file), it is key-cert-together.pem
            sender_certs = sign

        try:
            sender_certs = load_pem_x509_certificates(sender_certs)
        except ValueError as e:
            logger.warning(f"Certificate not found: {e}")
        if len(sender_certs) == 0:
            raise ValueError("Certificate not found")

        # get senders private key for signing
        try:
            # sign file has certificate
            sender_key = load_pem_private_key(sign, password=self._passphrase)
        except ValueError as e:
            print(f"Error loading private key: {e}")
        except TypeError as t:
            # TODO: do something more usefull
            print(f"Password not needed")

        # sign the message first
        signature_builder = pkcs7.PKCS7SignatureBuilder().set_data(email)
        signature_builder = signature_builder.add_signer(sender_certs[0], sender_key, hash_algorithm=hashes.SHA256())
        # add the whole certificate chain
        for cert in sender_certs[1:]:
            signature_builder = signature_builder.add_certificate(cert)
        signed_email = signature_builder.sign(serialization.Encoding.SMIME, [pkcs7.PKCS7Options.DetachedSignature])

        # get recipent's certificate for encryption
        if self._cert:
            pubkey = self._cert
        else:
            pubkey = encrypt

        certificates = encrypt

        recipient_certs = []
        for cert in certificates:
            try:
                c = load_pem_x509_certificate(cert)
            except ValueError as e:
                raise ValueError("failed to load certificate from file")

            recipient_certs.append(c)
        try:
            pubkey = load_pem_x509_certificate(pubkey)
        except ValueError as e:
            raise ValueError("failed to load certificate from file")

        # encrypt signed email with recipient's cert
        envelope_builder = pkcs7.PKCS7EnvelopeBuilder().set_data(signed_email)
        envelope_builder = envelope_builder.add_recipient(pubkey)

        for recip in recipient_certs:
            envelope_builder = envelope_builder.add_recipient(recip)

        options = [pkcs7.PKCS7Options.Binary]
        encrypted_email = envelope_builder.encrypt(serialization.Encoding.SMIME, options)
        return encrypted_email

    def _smime_encrypt_only(self, email, encrypt):

        _, pkcs7, _, load_pem_x509_certificate, _, serialization = self._import_cryptoraphy_modules()

        if self._cert:
            certificates = [self._cert]
        else:
            certificates = encrypt

        recipient_certs = []
        for cert in certificates:
            try:
                c = load_pem_x509_certificate(cert)
            except ValueError as e:
                raise ValueError("failed to load certificate from file")

            recipient_certs.append(c)

        options = [pkcs7.PKCS7Options.Binary]
        encrypted_email = pkcs7.PKCS7EnvelopeBuilder().set_data(email)

        for recip in recipient_certs:
            encrypted_email = encrypted_email.add_recipient(recip)

        encrypted_email = encrypted_email.encrypt(serialization.Encoding.SMIME, options)

        return encrypted_email

    def _encrypt_smime_now(self, email, sign, encrypt: Union[None, bool, bytes, list[bytes]]):
        """

        :type encrypt: Can be None, False, bytes or list[bytes]
        """

        # passphrase has to be bytes
        if (self._passphrase is not None):
            self._passphrase = self._passphrase.encode('utf-8')

        if sign is not None and type(sign) != bool:
            sign = assure_fetched(sign, bytes)

        if sign and not encrypt:
            output = self._smime_sign_only(email, sign)

        elif sign and encrypt:
            output = self._smime_sign_encrypt(email, sign, encrypt)

        elif not sign and encrypt:
            output = self._smime_encrypt_only(email, encrypt)

        return output

    def _compose_gpg_encrypted(self, text):
        # encrypted message structure according to RFC3156
        email = EmailMessage()
        # real subject might be hidden until decrypted
        email["Subject"] = ("Encrypted message" if self._subject_encrypted is True else self._subject_encrypted) \
            if self._subject_encrypted else self._subject
        email.set_type("multipart/encrypted")
        email.set_param("protocol", "application/pgp-encrypted")
        msg_version = EmailMessage()
        msg_version["Content-Type"] = "application/pgp-encrypted"
        msg_version.set_payload("Version: 1")
        msg_text = EmailMessage()
        msg_text["Content-Type"] = 'application/octet-stream; name="encrypted.asc"'
        msg_text["Content-Description"] = "OpenPGP encrypted message"
        msg_text["Content-Disposition"] = 'inline; filename="encrypted.asc"'
        msg_text.set_payload(text)  # text was replaced by a GPG stream
        email.attach(msg_version)
        email.attach(msg_text)
        return email
