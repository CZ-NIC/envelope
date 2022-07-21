import logging
from email import header, message_from_string, message_from_bytes
from email.message import Message
from os import environ
from typing import List

from .constants import smime_import_error, gnupg, PLAIN, HTML, SAFE_LOCALE

logger = logging.getLogger(__name__)


class Parser:

    def __init__(self, envelope: 'Envelope' = None, key=None, cert=None, gnupg_home=None):
        self.e = envelope
        self.key = key
        self.cert = cert
        self.gnupg_home = gnupg_home

    def parse(self, o: Message, add_headers=False):
        if add_headers:
            for k, val in o.items():
                # We skip "Content-Type" and "Content-Transfer-Encoding" since we decode text payload before importing.
                # We skip MIME-Version since it may be another one
                # in an encrypted sub-message we take the headers from too.
                if k.lower() in ("content-type", "content-transfer-encoding", "mime-version"):
                    continue
                try:
                    if isinstance(val, header.Header):
                        # when diacritics appear in Subject, object is returned instead of a string
                        # when maxline is not set, it uses a default one (75 chars?)
                        # and gets encoded into multiple chunks
                        # while policy.header_store_parse parses just the first
                        # val = val.encode()
                        self.e.header(k, val)
                    else:
                        self.e.header(k, " ".join(x.strip() for x in val.splitlines()))
                except ValueError as e:
                    logger.warning(f"{e} at header {k}")

        maintype, subtype = o.get_content_type().split("/")
        if o.is_multipart():
            payload: List[Message] = o.get_payload()
            if subtype == "alternative":
                [self.parse(x) for x in payload]
            elif subtype in ("related", "mixed"):
                for p in payload:
                    if p.get_content_maintype() in ["text", "multipart"] \
                            and p.get_content_disposition() != "attachment":
                        self.parse(p)
                    else:
                        # decode=True -> strip CRLFs, convert base64 transfer encoding to bytes etc
                        self.e.attach(p.get_payload(decode=True),
                                      mimetype=p.get_content_type(),
                                      name=p["Content-ID"] or p.get_filename(),
                                      inline=bool(subtype == "related"))
            elif subtype == "signed":
                for p in payload:
                    if p.get_content_type() == o.get_param("protocol"):  # ex: application/x-pkcs7-signature
                        continue  # XX we might verify signature
                    else:
                        self.parse(p)
            elif subtype == "encrypted":
                for p in payload:
                    if p.get_content_type() == o.get_param("protocol"):  # ex: application/pgp-encrypted
                        continue
                    elif p.get_content_type() == "application/octet-stream":
                        self.parse(message_from_string(self.gpg_decrypt(p.get_payload(decode=True))), add_headers=True)
                    else:
                        raise ValueError(f"Cannot decrypt.")
            else:
                raise ValueError(f"Subtype {subtype} not implemented")
        elif maintype == "text":
            if subtype in (HTML, PLAIN):
                t = o.get_payload(decode=True).strip()
                if o.get_charsets() and o.get_charsets()[0]:
                    try:
                        t = t.decode(o.get_charsets()[0])
                    except LookupError as e:
                        t = t.decode(errors="replace")
                        logger.warning(f"Replacing some invalid characters in {maintype}/{subtype}: {e}")
                    except ValueError as e:
                        t = t.decode(o.get_charsets()[0], errors="replace")
                        logger.warning(f"Replacing some invalid characters in {maintype}/{subtype}: {e}")
                self.e.message(t, alternative=subtype)
            else:
                raise ValueError(f"Unknown subtype: {subtype}")
        elif maintype == "application" and subtype == "x-pkcs7-mime":  # decrypting S/MIME
            self.parse(message_from_bytes(self.smime_decrypt(o.as_bytes())), add_headers=True)
        else:
            raise ValueError(f"Unknown maintype: {maintype}")
        return self.e

    def gpg_decrypt(self, data):
        g = gnupg.GPG(gnupghome=self.gnupg_home, env=dict(environ, LC_ALL=SAFE_LOCALE))
        output = g.decrypt(data)
        if output.ok:
            return str(output)
        else:
            raise ValueError(f"Cannot decrypt GPG data. " + output.status)

    def smime_decrypt(self, data):
        key = self.key
        cert = self.cert
        try:
            from M2Crypto import BIO, Rand, SMIME, X509, EVP  # we save up to 30 - 120 ms to load it here
        except ImportError:
            raise ImportError(smime_import_error)

        # Load private key and cert and decrypt
        s = SMIME.SMIME()
        s.load_key(key, cert)
        p7, data = SMIME.smime_load_pkcs7_bio(BIO.MemoryBuffer(bytes(data)))
        try:
            return s.decrypt(p7)
        except SMIME.PKCS7_Error:
            return False
