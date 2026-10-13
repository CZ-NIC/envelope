"""Signing methods of `Envelope`: the public `signature`/`sign`/`gpg`/`smime` plus GPG/S-MIME signing helpers.
Also holds GPG helpers shared with encryption (`_determine_gpg`, keyring access, `_import_cryptoraphy_modules`).
Mixin: shares one `self` with `Envelope`; nothing here is meant to be used standalone.
"""
import logging
import re
from tempfile import NamedTemporaryFile
from email.message import EmailMessage
from os import environ
from pathlib import Path
from typing import Any

from .address import _getaddresses
from .constants import smime_import_error, gnupg, AUTO, SAFE_LOCALE
from .utils import Fetched, is_gpg_importable_key, assure_list, assure_fetched

logger = logging.getLogger("envelope.envelope")  # same logger name as before the split


class _SigningMixin:
    def gpg(self, gnugp_home=True):
        """
        :param gnugp_home: String for GnuPG home or True.
        """
        self._gpg = gnugp_home
        return self

    def smime(self):
        self._gpg = False
        return self

    def signature(self, key: Any = True, passphrase=None, attach_key=None, cert=None, *, key_path=None):
        """
        Turn signing on.
        :param key: Signing key
            * GPG:
                * True (blank) for the user default key
                * "auto" for turning on signing if there is a key matching to the "from" header
                * key ID/fingerprint
                * e-mail address of the identity whose key is to be signed with
                * Any attainable contents with the key to be signed with (will be imported into keyring)
            * S/MIME: Any attainable contents with key to be signed with. May contain signing certificate as well.
        :param passphrase: Passphrase to the signing key if needed.
        :param attach_key: If True, append GPG public key as an attachment when sending.
        :param cert: S/MIME: Any attainable contents with certificate to be signed with.
        :param key_path: Path to a file with the `key`.
        """
        if key_path:
            key = Path(key_path)
        if key is True and self._sign not in [None, False]:
            # use case envelope().signature(key=fingerprint).send(sign=True) should still have fingerprint in self._sign
            # (and not just "True")
            pass
        elif key is not None:
            # GPG: True, AUTO, fingerprint, or attainable contents, S/MIME: attainable bytes
            self._sign = assure_fetched(key)  # possible types: True, AUTO, str, bytes
        if passphrase is not None:
            self._passphrase = passphrase
        if attach_key is not None:
            self._attach_key = attach_key
        if cert is not None:
            if self._gpg is None:  # since cert is only for S/MIME, set S/MIME signing
                self.smime()
                self._gpg = False
            self._cert = assure_fetched(cert, bytes)
        return self

    def sign(self, key=True, passphrase=None, attach_key=False, cert=None, *, key_path=None):
        """
        Sign now.
        :param key: Signing key
            * GPG:
                * True (blank) for the user default key
                * "auto" for turning on signing if there is a key matching to the "from" header
                * key ID/fingerprint
                * e-mail address of the identity whose key is to be signed with
                * Any attainable contents with the key to be signed with (will be imported into keyring)
            * S/MIME: Any attainable contents with key to be signed with. May contain signing certificate as well.
        :param passphrase: Passphrase to the key if needed.
        :param attach_key: GPG: Append public key to the attachments when sending.
        :param cert: S/MIME: Any attainable contents with certificate to be signed with.
        :param key_path: Path to a file with the `key`.
        """
        self._processed = True
        self.signature(key=key, passphrase=passphrase, attach_key=attach_key, cert=cert, key_path=key_path)
        self._start()
        return self

    def _determine_gpg(self, encrypt: Fetched | list[Fetched], sign: Fetched):
        """ determine if we are using gpg or smime"""
        gpg_on = None
        if encrypt or sign:
            if self._gpg is not None:
                gpg_on = bool(self._gpg)
            else:
                gpg_on = not self._is_smime_loadable(encrypt, sign)

            if gpg_on:
                self._gnupg = gnupg.GPG(gnupghome=self._get_gnupg_home(), options=["--trust-model=always"],
                                        # XX trust model might be optional
                                        env=dict(environ, LC_ALL=SAFE_LOCALE),
                                        verbose=False) if sign or encrypt else None
                # assure `sign` become either fingerprint of an imported key or None
                if sign:
                    if sign in [True, AUTO]:  # try to determine sign based on the "From" header
                        fallback_sign = sign = None
                        address_searched = self._from.address if self._from else False
                        if not address_searched:
                            # there is no "From" header (or the "From" header address is empty)
                            # and no default key is given, pick the first secret as a default
                            for key in self._gnupg.list_keys(True):
                                fallback_sign = key["keyid"]
                                break
                        else:
                            # sign = first available private keyid (fingerprint) or False
                            sign = next((key["keyid"] for key, address in self._gpg_list_keys(True)
                                         if address_searched == address), False)
                        if not sign and self._sign != AUTO:
                            if fallback_sign:
                                sign = fallback_sign
                            else:
                                raise RuntimeError("No GPG sign key found")
                    elif is_gpg_importable_key(sign):
                        # sign is Path or key contents, import it and get its fingerprint
                        sign = self._gpg_import_or_fail(sign)[0]

                if encrypt:
                    if encrypt == AUTO:
                        # encrypt = True only if there exists a key for every needed address
                        addresses_searched = self._get_decipherers()
                        [addresses_searched.discard(address) for _, address in self._gpg_list_keys(False)]
                        if addresses_searched:
                            encrypt = False
                    elif encrypt is not True:
                        # since encrypt may contain a mix of e-mail addresses, fingerprints, IDs and raw keys,
                        # we turn the raw keys into IDs.
                        # Such list can be passed as recipients to the gpg.encrypt method.
                        decipherers = []
                        for item in assure_list(encrypt):
                            if is_gpg_importable_key(item):
                                decipherers.extend(self._gpg_import_or_fail(item))
                            else:
                                decipherers.append(item)
                        encrypt = decipherers

        return encrypt, sign, gpg_on

    def _gpg_import_or_fail(self, key):
        """
        :param key: Any attainable contents
        :raises ValueError: If import failed
        :return: Fingerprints
        """
        if imported := self._gnupg.import_keys(assure_fetched(key, bytes)):
            return imported.fingerprints
        else:
            raise ValueError(f"Could not import key starting: {key[:80]}...")

    def _get_gnupg_home(self, for_help=False):
        s = self._gpg if type(self._gpg) is str else None
        if for_help:
            return f"GNUPGHOME={s} " if s else ""
        return s

    def _sign_gpg_now(self, message, sign, send):
        status = self._gnupg.sign(
            message,
            extra_args=["--textmode"],
            # textmode: Enigmail had troubles to validate even though signature worked in CLI https://superuser.com/questions/933333
            keyid=sign,
            passphrase=self._passphrase if self._passphrase else None,
            detach=True if send is not None else None,
        )
        # if the sign key is not found and there exists a secret key in the ring, the latter is used
        # with `gpg: all values passed to '--default-key' ignored`
        if sign and not re.search(r'gpg: using "[^"]+" as default secret key for signing', status.stderr):
            logger.warning(f"The secret key for {sign} seems to not be used,"
                           f" check if it is in the keyring: {self._get_gnupg_home(True)}gpg --list-secret-keys")
            return False, None
        try:  # micalg according to rfc4880
            micalg = "pgp-" + {1: "MD5",
                               2: "SHA1",
                               3: "RIPEMD160",
                               8: "SHA256",
                               9: "SHA384",
                               10: "SHA512",
                               11: "SHA224"}[int(status.hash_algo)].lower()
        except KeyError:  # alright, just unknown algorithm
            micalg = None
        except TypeError:  # signature failed
            logger.warning(status.stderr)
            return False, None
        return status.data, micalg

    def _gpg_list_keys(self, secret=False):
        return ((key, address) for key in self._gnupg.list_keys(secret) for _, address in _getaddresses(key["uids"]))

    def _gpg_verify(self, signature: bytes, data: bytes):
        """ Allows verifying detached GPG signature.
        * As parameters are not user-friendly
        * it is not trivial to get them from an arbitrary message
        * no possibility to specify the key
        the method may change. Therefore, it is not considered public.
         """
        with NamedTemporaryFile() as fp:
            fp.write(signature)
            fp.seek(0)
            return bool(self._gnupg.verify_data(fp.name, data))

    def _is_smime_loadable(self, encrypt: Fetched | list[Fetched], sign: Fetched) -> bool:
        """ Whether the contents to sign with is a PEM private key, or the contents to encrypt with are certificates. """
        try:
            load_pem_private_key, _, _, load_pem_x509_certificate, *_ = self._import_cryptoraphy_modules()
        except ImportError:
            # Do not let an S/MIME key or certificate be misinterpreted as a GPG key without the S/MIME extra.
            if any(isinstance(c, bytes) and re.search(rb"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----", c)
                   for c in [sign, *assure_list(encrypt)]):
                raise
            return False
        try:
            if sign:
                load_pem_private_key(sign, password=None)
            else:
                [load_pem_x509_certificate(e) for e in assure_list(encrypt)]
        except TypeError:  # not bytes (ex: True, a fingerprint), or a key protected by a passphrase not passed here
            return bool(sign) and isinstance(sign, bytes)
        except ValueError:
            return False
        return True

    def _import_cryptoraphy_modules(self):
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs7
            from cryptography.x509 import load_pem_x509_certificates, load_pem_x509_certificate
            from cryptography.hazmat.primitives import hashes, serialization
            return load_pem_private_key, pkcs7, load_pem_x509_certificates, load_pem_x509_certificate, hashes, serialization
        except ImportError:
            raise ImportError(smime_import_error)

    def _smime_load_signer(self, sign):
        """ :return: (certificate chain, private key) of the sender """
        load_pem_private_key, _, load_pem_x509_certificates, *_ = self._import_cryptoraphy_modules()
        # get sender's cert
        # cert and private key can be one file

        # if certfile is not provided, sign has to have both private key and certificate
        # cert is not in sign (--sign_path file), it is cert.pem
        if self._cert:
            certs = self._cert
        else:
            # certificate is in sign (--sign_path file), it is key-cert-together.pem
            certs = sign

        try:
            certs = load_pem_x509_certificates(certs)
        except ValueError as e:
            raise ValueError(f"Certificate not found: {e}")
        # no certificate found
        if len(certs) == 0:
            raise ValueError("Certificate not found")

        # get senders private key for signing
        try:
            # sign file has certificate
            password = self._passphrase.encode("utf-8") if isinstance(self._passphrase, str) else self._passphrase
            key = load_pem_private_key(sign, password=password)
        except ValueError as e:
            raise ValueError(f"Error loading private key: {e}")
        except TypeError:
            raise TypeError("Wrong passphrase or passphrase is not needed")
        return certs, key

    def _smime_sign_only(self, email, sign, signer=None):
        """
        :param signer: (certificate chain, private key) if already loaded by `_smime_load_signer`
        """
        _, pkcs7, _, _, hashes, serialization = self._import_cryptoraphy_modules()
        certs, key = signer or self._smime_load_signer(sign)

        options = [pkcs7.PKCS7Options.DetachedSignature]

        signature_builder = pkcs7.PKCS7SignatureBuilder().set_data(
            email
        ).add_signer(
            certs[0], key, hashes.SHA256()
        )
        # add the whole certificate chain
        for cert in certs[1:]:
            signature_builder = signature_builder.add_certificate(cert)

        signed_email = signature_builder.sign(
            serialization.Encoding.SMIME, options
        )

        return signed_email

    def _compose_gpg_signed(self, email, text, micalg=None):
        msg_payload = email
        email = EmailMessage()
        email["Subject"] = self._subject
        email.set_type("multipart/signed")
        email.set_param("protocol", "application/pgp-signature")
        if micalg:
            email.set_param("micalg", micalg)
        email.attach(msg_payload)
        msg_signature = EmailMessage()
        msg_signature['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
        msg_signature['Content-Description'] = 'OpenPGP digital signature'
        msg_signature['Content-Disposition'] = 'attachment; filename="signature.asc"'
        msg_signature.set_payload(text)
        email.attach(msg_signature)
        return email
