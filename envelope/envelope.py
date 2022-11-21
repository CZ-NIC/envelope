#!/usr/bin/env python3
import binascii
import logging
import re
import smtplib
import subprocess
import sys
from tempfile import NamedTemporaryFile
from unittest import mock
import warnings
from base64 import b64decode
from configparser import ConfigParser
from copy import deepcopy
from email import message_from_bytes
from email.header import decode_header
from email.generator import Generator
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import make_msgid, formatdate, getaddresses
from getpass import getpass
from itertools import chain
from os import environ
from pathlib import Path
from quopri import decodestring
from types import GeneratorType
from typing import Union, List, Set, Optional, Any

from .constants import smime_import_error, gnupg, CRLF, AUTO, PLAIN, HTML, SIMULATION, SAFE_LOCALE
from .parser import Parser
from .utils import Address, Attachment, AutoSubmittedHeader, SMTPHandler, _Message, \
    is_gpg_importable_key, assure_list, assure_fetched, get_mimetype

__doc__ = """Quick layer over python-gnupg, M2Crypto, smtplib, magic and email handling packages.
Their common use cases merged into a single function. Want to sign a text and tired of forgetting how to do it right?
You do not need to know everything about GPG or S/MIME, you do not have to bother with importing keys.
Do not hassle with reconnecting to an SMTP server. Do not study various headers meanings
to let your users unsubscribe via a URL. You insert a message, attachments and inline images
and receive signed and/or encrypted output to the file or to your recipients' e-mail.
Just single line of code.

Envelope("my message")
    .subject("hello world")
    .to("example@example.com")
    .attach(file_contents, name="attached-file.txt")
    .smtp("localhost", 587, "user", "pass", "starttls")
    .signature()
    .send()

Usage:
  * launch as an application, see ./envelope.py --help
  * import as a module to your application, ex: `from envelope import Envelope` 
"""

logger = logging.getLogger(__name__)


class Envelope:
    _gnupg: gnupg.GPG

    def __bool__(self):
        return self._status

    def __str__(self):
        self._result_fresh()
        if not self._result:
            if self._encrypt or self._sign:
                # if subject is not set, we suppose this is just a data blob to be encrypted, not an e-mail message
                # and a ciphered blob will get output. However, if subject is set, we put send=SIMULATION
                # in order to display all e-mail headers etc.
                is_email = SIMULATION if bool(self._subject) else False
                self._start(send=is_email)
            else:
                # nothing to do, let's assume this is a bone of an e-mail by appending `--send False` flag
                # to produce an output
                self._start(send=SIMULATION)
        return self._get_result_str()

    def __repr__(self):
        """
        :return: Prints out basic representation.
         However, this is not a serialization: you cannot reconstruct any complicated objects
         having attachments or custom headers.
        """

        def quote(x):
            return '"' + x.replace('"', r'\"') + '"' if type(x) is str else x

        o = []

        text, html = self._message.get(str)
        message = {}
        if text and html:
            message = {"message(html)": html,
                       "message(plain)": text}
        elif text or html:
            message = {"message": text or html}
        o.extend(f'{k}={quote(v)}' for k, v in {"subject": self._subject,
                                                "from_": self._from,
                                                "to": self._to,
                                                "cc": self._cc,
                                                "bcc": self._bcc,
                                                "reply_to": self._reply_to,
                                                "from_addr": self._from_addr,
                                                "signature": self._sign,
                                                "encryption": self._encrypt,
                                                **message
                                                }.items() if v)

        if not o:
            return super().__repr__()
        return f"Envelope({', '.join(o)})"

    def __bytes__(self):
        self._result_fresh(True)
        return assure_fetched(self._get_result_str(), bytes)

    def __eq__(self, other):
        self._result_fresh(True)
        me = assure_fetched(self._get_result_str(), bytes)
        if type(other) in [str, bytes]:
            return me == assure_fetched(other, bytes)
        elif isinstance(other, Envelope):
            return me == bytes(other)

    def preview(self):
        """ Returns the string of the message or data as a human-readable text.
            Bcc and attachments are mentioned.
            Ex: whilst we have to use quoted-printable, here the output will be plain text.
        """
        self._result_fresh(True)
        result = []
        for a in self._attachments:  # include attachments info as they are removed with the payload later
            if a.inline:
                s = f"Inline attachment {a.preview()}"
            else:
                s = f"Attachment {a.preview()}"
            result.append(s)

        if self._bcc:  # as bcc is not included as an e-mail header, we explicitly state it here
            result.append("Bcc: " + ", ".join(map(str, self._bcc)))

        for r in self._result:
            if isinstance(r, Message):  # smime library always produces a Message object, otherwise EmailMessage is got
                if self._sign or self._encrypt:
                    result.append(("GPG" if self._gpg else "S/MIME") + ": " + ", ".join(
                        x for x in [bool(self._sign) and "signed", bool(self._encrypt) and "encrypted"] if x))

                # append headers
                [result.append(f"{key}: {val}") for key, val in r.items()]
                result.append("")
            else:
                result.append(r)

        text, html = self._message.get(str)
        if text and html:
            result.extend(["* MESSAGE VARIANT text/plain:", text, "",
                           "* MESSAGE VARIANT text/html:", html])
        else:
            result.append(self.message())
        return "\n".join(result)

    def _get_result_str(self):
        """ concatenate output string """
        if not self._result_cache:
            with mock.patch.object(Generator, '_handle_multipart_signed', Generator._handle_multipart):
                # https://github.com/python/cpython/issues/99533 and #19
                s = "\n".join(str(r) for r in self._result)
            self._result_cache = s  # slightly quicker next time if ever containing a huge amount of lines
        return self._result_cache

    def _result_fresh(self, recreate=False):
        if self._result_cache_hash and self._result_cache_hash != self._param_hash():
            # ex: if we change Subject, we have to regenerate self._result
            self._result.clear()
        if recreate and not self._result:
            str(self)

    def as_message(self) -> Message:
        """
        :return: Message object is S/MIME is used, EmailMessage otherwise.
        Note: due to an internal Python bug https://github.com/python/cpython/issues/99533 and #19
        you receive void GPG when signing an attachment with a name longer than 34 chars.
        """
        self._result_fresh()
        for el in self._result:
            if isinstance(el, Message):
                return el
        return self._start(send=SIMULATION)

    @staticmethod
    def load(message=None, *, path=None, key=None, cert=None, gnupg_home=None) -> "Envelope":
        """
        XX make it capable to verify signatures
        XX option to specify the GPG decrypting key
        XX make key and cert work from bash too and do some tests

        Note that if you will send this reconstructed message, you might not probably receive it
        due to the Message-ID duplication. Delete at least Message-ID header prior to re-sending.

        :param message: Any attainable contents to build an Envelope object from, including email.message.Message.
        :param path: (Alternative to `message`.) Path to the file that should be loaded.
        :param key: S/MIME key to decrypt with.
        :param cert: S/MIME cert to decrypt with. (If not bundled with the key.)
        :param gnupg_home: Path to the GNUPG_HOME or None if the environment default should be used.
        """
        if path:
            message = Path(path)
        elif isinstance(message, Message):
            message = str(message)

        o = message_from_bytes(assure_fetched(message, bytes))
        e = Envelope()
        try:
            return Parser(e, key=key, cert=cert, gnupg_home=gnupg_home or e._get_gnupg_home()) \
                .parse(o, add_headers=True)
        except ValueError as err:
            logger.warning(f"Message might not have been loaded correctly. {err}")

        # emergency body loading when parsing failed
        header_row = re.compile(r"([^\t:]+):(.*)")
        text = assure_fetched(message, str)
        is_header = True
        headers = []  # [whole line, header name, header val] XX var headers is not used, deprecated
        body = []
        for line in text.splitlines():
            if is_header:  # we are parsing e-mail template header first
                # are we still parsing the header?
                m = header_row.match(line)
                if m:
                    headers.append([line, m.group(1).strip(), m.group(2).strip()])
                    continue
                else:
                    if line.startswith(("\t", " ")) and headers:  # this is not end of header, just line continuation
                        headers[-1][0] += " " + line.strip()
                        headers[-1][2] += " " + line.strip()
                        continue
                    is_header = False  # header has ended
                    if line.strip() == "":  # next line will be body
                        continue
                    else:  # header is missing or incorrect, there is body only
                        body = [h[0] for h in headers]
                        headers = []
            if not is_header:
                body.append(line)

        e.message(CRLF.join(body))
        # for _, key, val in header:
        #     e.header(key, val)
        return e

    def __init__(self, message=None, from_=None, to=None, subject=None, headers=None, from_addr=None,
                 gpg=None, smime=None,
                 encrypt=None, sign=None, passphrase=None, attach_key=None, cert=None, subject_encrypted=None,
                 sender=None, cc=None, bcc=None, reply_to=None, mime=None, attachments=None,
                 smtp=None, output=None, send=None):
        """
        :rtype: object If output not set, return output bytes, else True/False if output file was correctly written to.

        Any attainable contents means plain text, bytes or stream (ex: from open()).
        In *module interface*, you may use Path object to the file.
        In *CLI interface*, additional flags are provided.

        Output
        :param message: Any attainable contents.
        :param output: Path to file to be written to (else the contents is returned).
        :param gpg: Home folder of GNUPG rings else default ~/.gnupg is used. Put True for prefer GPG over S/MIME.
        :param smime: Prefer S/MIME over GPG.

        Signing
        :param sign: True or key id if the message is to be signed. S/MIME certificate key or Path or stream (ex: from open()).
        :param passphrase: Passphrase to the signing key if needed.
        :param attach_key: If True, append GPG public key as an attachment when sending.
        :param cert: S/MIME certificate contents or Path or stream (ex: from open()) if certificate not included in the key.

        Encrypting
        :param encrypt: Recipients public key string or Path or stream (ex: from open()).
        :param subject_encrypted: Text used instead of the real protected subject while PGP encrypting. False to not encrypt.
        :param to: E-mail or more in an iterable. If encrypting used so that we choose the key they will be able to decipher with.
        :param from_: E-mail of the sender. If encrypting used so that we choose our key to be still able
                        to decipher the message later with.
                        If False, we explicitly declare to give up on deciphering later.

        Input / Sending
        :param subject: E-mail subject
        :param reply_to: Reply to header
        :param mime: Set contents mime subtype: "html" (default) or "plain" for plain text
        :param smtp: tuple or dict of these optional parameters: host, port, username, password, security ("tlsstart").
            Or link to existing INI file with the SMTP section.
        :param send: True for sending the mail. False will just print the output.
        :param cc: E-mail or more in an iterable.
        :param bcc: E-mail or more in an iterable.
        :param attachments: Attachment or their list. Attachment is defined by file path or stream (ex: from open()),
            optionally in tuple with the file name in the e-mail and/or mimetype.
        :param headers: List of headers which are tuples of name, value. Ex: [("X-Mailer", "my-cool-application"), ...]
        :param sender: REMOVED, raises an informative error.
            Use Envelope().from_() or Envelope().header("Sender", ...) instead.
        :param from_addr: Envelope MAIL FROM address for SMTP.
        """
        # user defined variables
        self._message = _Message()
        self._output = None
        self._gpg: Union[str, bool, None] = None
        #   GPG: (True, key contents, fingerprint, AUTO, None) → will be converted to key fingerprint or None,
        #   S/MIME: certificate contents
        self._sign = None
        self._passphrase = None
        self._attach_key = None
        self._cert = None
        #   GPG: (True, key contents, fingerprint, None)
        #   SMIME: certificate contents
        self._encrypt = None

        # `self._from` might be false because of `from_=False` attribute (or "--no-from" flag)
        # that explicitly states we have no from header
        self._from: Union[Address, False, None] = None  # e-mail From header
        self._from_addr: Optional[Address] = None  # SMTP envelope MAIL FROM address
        self._to: List[Address] = []
        self._cc: List[Address] = []
        self._bcc: List[Address] = []
        self._reply_to: List[Address] = []
        self._subject: Union[str, None] = None
        self._subject_encrypted: Union[str, bool] = True
        self._smtp = None
        self._attachments: List[Attachment] = []
        self._mime = AUTO
        self._nl2br = AUTO
        self._headers = EmailMessage()  # object for storing headers the most standard way possible
        self._ignore_date : bool = False

        # variables defined while processing
        self._status : bool = False  # whether we successfully encrypted/signed/send
        self._processed : bool = False  # prevent the user from mistakenly call .sign().send() instead of .signature().send()
        self._result : List[Union[str, EmailMessage, Message]] = []  # text output for str() conversion
        self._result_cache : Optional[str] = None
        self._result_cache_hash : Optional[int] = None
        self._smtp = SMTPHandler()
        self.auto_submitted = AutoSubmittedHeader(self)  # allows fluent interface to set header

        # init parameters with appropriate methods
        self._populate(locals())

    @staticmethod
    def _get_private_var(k):
        """ Gets internal specific interface var name from its method name. """
        if k == "from_":
            k = "from"
        return "_" + k

    def _populate(self, params):
        for k, v in params.items():
            if k in ["self", "send"]:  # send must be the last
                continue
            elif k == "smime":  # smime uses _gpg, not _smime because it needs no parameter
                if v is True:
                    self.smime()
                continue
            elif v is None:
                continue

            if k == "passphrase":
                self.signature(passphrase=v)
            elif k == "attach_key":
                if v is True:
                    self.signature(attach_key=v)
            elif k == "cert":
                self.signature(None, cert=v)
            elif k == "attachments":
                # as a tuple with a single attachment (and its details) is allowed here,
                # we have to distinguish from a list that contains multiple attachments
                if isinstance(v, tuple):
                    v = [v]
                self.attach(v)
            elif k == "headers":  # [(header-name, val), ...]
                for it in v:
                    self.header(*it)
            elif k == "sign":
                self.signature(v)
            elif k == "encrypt":
                self.encryption(v)
            elif k == "subject_encrypted":
                self.subject(encrypted=v)
            elif v is not None and v != []:  # "to" will receive [] by default
                getattr(self, k)(v)  # ex: self.message(message)

        if params.get("sign") or params.get("encrypt") or params.get("send") is not None:
            self._start(send=params.get("send"))
        return self

    def copy(self) -> "Envelope":
        """ Returns deep copy of the object. """
        return deepcopy(self)

    @staticmethod
    def _parse_addresses(registry, email_or_more):
        addresses = assure_list(email_or_more)
        if any(not x for x in addresses):
            registry.clear()
        addresses = [x for x in addresses if x]  # filter out possible "" or False
        if addresses:
            registry += (a for a in Address.parse(addresses) if a not in registry)

    def to(self, email_or_more=None) -> Union["Envelope", List[Address]]:
        """ Multiple addresses may be given in a string, delimited by comma (or semicolon).
         (The same is valid for `to`, `cc`, `bcc` and `reply-to`.)

            :param email_or_more: str|Tuple[str]|List[str]|Generator[str]|Set[str]|Frozenset[str]
             Set e-mail address/es. If None, we are reading.
            return: Envelope if `email_or_more` set or List[Address] if not set
        """
        if email_or_more is None:
            return self._to
        self._parse_addresses(self._to, email_or_more)
        return self

    def cc(self, email_or_more=None) -> Union["Envelope", List[Address]]:
        if email_or_more is None:
            return self._cc
        self._parse_addresses(self._cc, email_or_more)
        return self

    def bcc(self, email_or_more=None) -> Union["Envelope", List[Address]]:
        if email_or_more is None:
            return self._bcc
        self._parse_addresses(self._bcc, email_or_more)
        return self

    def reply_to(self, email_or_more=None) -> Union["Envelope", List[Address]]:
        if email_or_more is None:
            return self._reply_to
        self._parse_addresses(self._reply_to, email_or_more)
        return self

    def body(self, text=None, *, path=None):
        """ An alias of .message """
        return self.message(text=text, path=path)

    def text(self, text=None, *, path=None):
        """ An alias of .message """
        return self.message(text=text, path=path)

    def message(self, text=None, *, path=None, alternative=AUTO, boundary=None) -> Union["Envelope", str]:
        """
        Message to be ciphered / e-mail body text.
        :param text: Any attainable contents.
        :param path: Path to the file.
        :param alternative: "auto", "html", "plain" You may specify e-mail text alternative.
         Some e-mail readers prefer to display plain text version over HTML.
          By default, we try to determine content type automatically (see *mime*).
        :param boundary: When specifying alternative, you may set e-mail boundary if you do not wish a random one to be created.

        Example:
            print(Envelope().message("He<b>llo</b>").message("Hello", alternative="plain"))

            # (output shortened)
            # Content-Type: multipart/alternative;
            #  boundary="===============0590677381100492396=="
            #
            # --===============0590677381100492396==
            # Content-Type: text/plain; charset="utf-8"
            # Hello
            #
            # --===============0590677381100492396==
            # Content-Type: text/html; charset="utf-8"
            # He<b>llo</b>

        :return: Envelope if `text` or `path` is set
            otherwise return anything that has been inserted to the .message() before as `str`
        """
        # XX make preview default over send(0) when no action is given?
        if boundary is not None:
            self._message.boundary = boundary
        if alternative not in (AUTO, PLAIN, HTML):
            raise ValueError(f"Invalid alternative {alternative} for message,"
                             f" choose one of the: {AUTO}, {PLAIN}, {HTML}")
        if text is path is None:
            # reading value
            b = getattr(self._message, alternative)
            if not b and alternative == AUTO:  # prefer reading HTML over plain text if alternative set
                b = self._message.html or self._message.plain

            # When loading an EML, Content-Type and Content-Transfer-Encoding get wiped off and the message is decoded.
            # However, the user can define the headers explicitly.
            # In that case we expect the message is already inserted encoded. (However, if it not, we do our best.)

            # The user can define the Content-Type
            content_type = self._headers.get("Content-Type")
            m = re.search("charset=(.*)", content_type, re.IGNORECASE) if content_type else None
            charset = m[1] if m else "utf-8"

            # Content-Transfer-Encoding might be active
            transfer = self._headers.get("Content-Transfer-Encoding")
            if transfer == "base64":
                try:
                    return b64decode(b).decode(charset)
                except binascii.Error:
                    pass  # the user specified Content-Transfer-Encoding but left the message unencoded
                except UnicodeDecodeError:
                    raise TypeError(f"Cannot base64-decode the message: {b}")
            elif transfer == "quoted-printable":
                try:
                    return decodestring(b).decode(charset)
                except ValueError:
                    pass  # the user specified Content-Transfer-Encoding but left the message unencoded

            if b is None:
                return ""
            try:
                return b.decode(charset)
            except UnicodeError:
                raise ValueError(f"Cannot decode the message correctly, it is not in Unicode. {b}")

        # write value
        if path:
            text = Path(path)

        setattr(self._message, alternative, assure_fetched(text, bytes))
        return self

    def date(self, date):
        """
        Specify Date header. If not used, Date will be added automatically.
        :param date: str|False If False, the Date header will not be added automatically.
        """
        if date is False:
            if "Date" in self._headers:  # removes date header
                del self._headers["Date"]
            self._ignore_date = True
        else:
            self._ignore_date = False
            self.header("Date", date)
        return self

    def sender(self, email=None):
        """ REMOVED, raises an informative error. Use Envelope().from_() or Envelope().header("Sender", ...) instead."""
        raise NotImplementedError("Method Envelope().sender() has been deprecated and was removed due"
                                  " to the unambiguous naming clash between the From and the Sender e-mail header."
                                  ' Use Envelope().from_(...) and Envelope().header("Sender", ...) instead.')

    def from_(self, email=None) -> Union["Envelope", Address]:
        """ Set the `From` header. If None, current `From` returned. """
        if email is None:
            return self._from or Address()
        self._from = Address.parse(email, single=True, allow_false=True)
        return self

    def from_addr(self, email=None) -> Union["Envelope", Address]:
        if email is None:
            return self._from_addr or Address()
        self._from_addr = Address.parse(email, single=True)
        return self

    def output(self, output_file):
        self._output = output_file
        return self

    def gpg(self, gnugp_home=True):
        """
        :param gnugp_home: String for GnuPG home or True.
        """
        self._gpg = gnugp_home
        return self

    def smime(self):
        self._gpg = False
        return self

    def subject(self, subject=None, encrypted: Union[str, bool] = None) -> Union["Envelope", str]:
        """ Get or set the message subject
        :param subject: Subject text.
        :param encrypted: Text used instead of the real protected subject while PGP encrypting. False to not encrypt.
        :return If neither parameter specified, current subject returned, otherwise return self.
        """
        if subject is None and encrypted is None:
            return str(self._subject or "")
        if subject is not None:
            self._subject: str = subject
        if encrypted is not None:
            self._subject_encrypted = encrypted
        return self

    def mime(self, subtype=AUTO, nl2br=AUTO):
        """
        Ignored if `Content-Type` header put to the message.
        @type subtype: str Set contents mime subtype: "auto" (default), "html" or "plain" for plain text.
        @param nl2br: True: envelope will append `<br>` to every line break in the HTML message.
                      "auto": line breaks are changed only if there is no `<br` or `<p` in the HTML message,
        """
        self._mime = subtype
        self._nl2br = nl2br
        return self

    def list_unsubscribe(self, uri=None, one_click=False, *, web=None, email=None):
        """ The header will not be encrypted with GPG nor S/MIME.
        :param uri: Web or e-mail address.
            We try to determine whether this is e-mail and prepend brackets and 'https:'/'mailto:' if needed
            Ex: "me@example.com?subject=unsubscribe", "example.com/unsubscribe", "<https://example.com/unsubscribe>"
        :param one_click: If True, rfc8058 List-Unsubscribe-Post header is added.
            This says user can unsubscribe with a single click that is realized by a POST request
            in order to prevent e-mail scanner to access the unsubscribe page by mistake. A 'https' url must be present.
        :param web: URL. Ex: "example.com/unsubscribe", "http://example.com/unsubscribe"
        :param email: E-mail address. Ex: "me@example.com", "mailto:me@example.com"
        :return: self
        """

        elements = []
        if "List-Unsubscribe" in self._headers:
            elements.extend(self._headers["List-Unsubscribe"].split(","))

        if one_click:
            self.header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
            if uri and not web:  # we are sure this is web because one-click header does not go with an e-mail
                web = uri
                uri = None

        if uri.startswith("<"):
            elements.append(uri)
        elif uri.startswith(("http:", "https:", "mailto:", "//")):
            elements.append(f"<{uri}>")
        elif "@" in uri:
            elements.append(f"<mailto:{uri}>")
        else:
            elements.append(f"<https://{uri}>")

        if web:
            if uri.startswith(("http:", "https:", "//")):
                elements.append(f"<{web}>")
            else:
                elements.append(f"<https://{web}>")

        if email:
            if uri.startswith("mailto:"):
                elements.append(f"<{email}>")
            else:
                elements.append(f"<mailto:{email}>")

        self.header("List-Unsubscribe", ", ".join(elements), replace=True)
        return self

    auto_submitted: AutoSubmittedHeader

    def header(self, key, val=None, replace=False) -> Union["Envelope", list, str, None]:
        """ Add a generic header.
        The header will not be encrypted with GPG nor S/MIME.
        :param key: str Header name
        :param val: str Header value. If None, currently used value is returned as string, or their list, or None.
        :param replace: bool If True, any header of the `key` name are removed first and if `val` is None, the header is deleted.
                        Otherwise another header of the same name is appended.
        :return: Envelope|str|list|None Returned self if `val` is not None or replace=True, else returns value of the header
                 or its list if the header was used multiple times. (Note that cc and bcc headers always return list.)
        """

        # lowercase header to its method name
        specific_interface = {"to": self.to, "cc": self.cc, "bcc": self.bcc, "reply-to": self.reply_to,
                              "from": self.from_, "subject": self.subject
                              }

        k = key.lower()

        if k in specific_interface:
            if replace:
                attr = getattr(self, self._get_private_var(k))
                setattr(self, self._get_private_var(k), None if type(attr) is str else [])
                return self
            # Xif type(val) is str:  # None has to stay None
            # We have to type the value to `str` due to this strange fact:
            # `key = "subject"; email["Subject"] = policy.header_store_parse(key, "hello")[1];`
            #   would force `str(email)` output 'subject: hello' (small 's'!)
            # Interestingly, setting `key = "anything else";` would output correct 'Subject: hello'
            # val = str(policy.header_store_parse(k, val)[1])  # Subject '=?UTF-8?Q?Re=3a_text?=' -> 'Re: text'
            if val is not None:  # None has to stay None to allow reading
                # val might be str or header.Header (used when loading through message_from_bytes)
                # decode_header might return multiple chunks
                # ex: "To: Novák Honza Name longer than 75 chars <honza.novak@example.com>" -> single chunk
                #   [(b'Nov\xc3\xa1k Honza Name longer than 75 chars <honza.novak@example.com>', 'unknown-8bit')]
                # ex: "From: =?UTF-8?Q?Ji=c5=99=c3=ad?= <jiri@example.com>" -> multiple chunks
                #   [(b'Ji\xc5\x99\xc3\xad', 'utf-8'), (b' <jiri@example.com>', None)]
                val = "".join(assure_fetched(x[0], str) for x in decode_header(val))
            return specific_interface[k](val)

        if replace:
            del self._headers[key]
        if val is None and not replace:
            h = self._headers.get_all(key)
            if h and len(h) == 1:
                return h[0]
            return h
        elif val:
            try:
                self._headers[key] = val
            except TypeError as e:
                logger.warning(f"Header {key} could not be successfully loaded with {val}: {e}")
                self._headers[key] = str(val)
        return self

    def smtp(self, host: Any = "localhost", port=25, user=None, password=None, security=None, timeout=3, attempts=3,
             delay=3):
        """
        Obtain SMTP server connection.
        Note that you may safely call this in a loop,
            envelope will remember the settings and connect only once (without reconnecting every iteration).
        :param host: hostname, smtplib.SMTP, INI file path, or a list or dict with the parameters (see README.md)
        :param port:
        :param user:
        :param password:
        :param security: If not set, automatically set to `starttls` for port *587* and to `tls` for port *465*
        :param timeout: How many seconds should SMTP wait before timing out.
        :param attempts: How many times we try to send the message to an SMTP server.
        :param delay: How many seconds to sleep before re-trying a timed out connection.
        :return:
        """
        # CLI interface returns always a list or dict, ex: host=["localhost"] or host=["ini file"] or host={}
        # module one-liner interface fills host param, ex: host="localhost", host="ini file", host={"port": 123}, ["localhost", 123]
        # fluent interface fills all locals, ex: {"host": "ini file", "port": default 25}
        # check for the presence of an INI file
        ini = None
        if type(host) is str:
            ini = host
        elif type(host) is list and len(host) > 0:
            ini = host[0]
        elif type(host) is dict and "host" in host:
            ini = host["host"]

        if ini and ini.endswith("ini"):
            if not Path(ini).exists() and not Path(ini).is_absolute():
                # when imported as a library, the relative path to the ini file might point to the main program directory
                ini = Path(Path(sys.argv[0]).parent, ini)

            if Path(ini).exists():  # existing INI file
                config = ConfigParser()
                config.read(ini)
                try:
                    host = {k: v for k, v in config["SMTP"].items()}
                except KeyError as e:
                    raise FileNotFoundError(f"INI file {ini} exists but section [SMTP] is missing") from e

        if type(host) is dict:  # ex: {"host": "localhost", "port": 1234}
            self._smtp = SMTPHandler(**host)
        elif type(host) is list:  # ex: ["localhost", 1234]
            self._smtp = SMTPHandler(*host)
        elif isinstance(host, smtplib.SMTP):
            self._smtp = SMTPHandler(host)
        else:
            self._smtp = SMTPHandler(host, port, user, password, security, timeout=timeout, attempts=attempts,
                                     delay=delay)
        return self

    def attach(self, attachment=None, mimetype=None, name=None, inline=None, *, path=None):
        """

        :type attachment: Any attainable contents that should be added as an attachment or their list.
                The list may contain tuples: `any_attainable_contents [,mime type] [,file name] [, True for inline]`.
        :param mimetype: Mime type OR file name of the attachment.
        :param name: Mime type OR file name of the attachment.
        :param path: Path to the file that should be attached.
        :param inline: Set parameter content-id (CID) so that we may reference image from within HTML message body.
                       * str: The attachment will get this CID.
                       * True: Filename or attachment or path file name is set as CID.
                       Example:
                           .attach("file.jpg", inline=True) -> <img src='cid:file.jpg' />
                           .attach(b"GIF89a\x03\x00\x03...", filename="file.gif", inline=True) -> <img src='cid:file.gif' />
                           .attach("file.jpg", inline="foo") -> <img src='cid:foo' />
        """
        if isinstance(attachment, (tuple, list, GeneratorType, set, frozenset)):
            # putting all these types normally work, however, only list is acknowledged in the documentation for now
            if path or mimetype or name:
                raise ValueError("Cannot specify both path, mimetype or name and put a list in attachment.")
        else:
            if path:
                attachment = Path(path)
            attachment = [(attachment, mimetype, name, inline)]
        self._attachments += [Attachment(o) for o in assure_list(attachment)]
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

    def send(self, send=True, sign=None, encrypt=None):
        """
        Send e-mail contents. To check e-mail was successfully sent, cast the returned object to bool.
        :param send: True to send now, False to print debug information.
        :param sign: Turn signing on.
            The parameter will be passed as the `key` parameter of the .signature method.
            * GPG: Ex: True or default signing key ID/fingerprint.
            * S/MIME: Any attainable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use the full .signature() method instead.)
        :param encrypt: Turn encrypting on.
            The parameter will be passed as the `key` parameter of the .encryption method.
            Ex: Any attainable contents with recipient GPG public key or S/MIME certificate to be encrypted with.
        :return:
        """
        if self._processed:
            raise RuntimeError("Cannot call .send() after .sign()/.encrypt()."
                               " You probably wanted to use .signature()/.encryption() instead.")
        self._start(sign=sign, encrypt=encrypt, send=send)
        return self

    def _start(self, sign=None, encrypt=None, send=None):
        """ Start processing. Either sign, encrypt or send the message and possibly set bool status of the object to True.
        * send == SIMULATION is the same as send == False but the message "have not been sent" will not be produced
        """
        plain: bytes
        html: bytes
        data: bytes

        self._status = False
        if sign is not None:
            self.signature(sign)
        if encrypt is not None:
            self.encryption(encrypt)

        # sign:
        #   GPG: (True, key contents, fingerprint, AUTO, None) → will be converted to key fingerprint or None,
        #   SMIME: certificate contents
        sign = self._sign
        # encrypt:
        #   GPG: (True, key contents, fingerprint, None)
        #   SMIME: certificate contents
        encrypt = self._encrypt
        if sign is None and encrypt is None and send is None:  # check if there is something to do
            logger.warning("There is nothing to do – no signing, no encrypting, no sending.")
            return

        # assure streams are fetched and files are read from their paths
        plain, html = self._message.get()

        # we need a message
        if not any((plain, html)):
            logger.error("Missing message")
            return

        # determine if we are using gpg or smime
        encrypt, sign, gpg_on = self._determine_gpg(encrypt, sign)

        # if we plan to send later, convert text message to the email message object
        email : Optional[Union[str, EmailMessage, Message]] = None
        if send is not None or html:  # `html` means the user wants a 'multipart/alternative' e-mail message
            email = self._prepare_email(plain, html, encrypt and gpg_on, sign and gpg_on, sign)
            if not email:
                return
            data = email.as_bytes()
        else:
            data = plain

        # with GPG, encrypt or sign either text message or email message object
        micalg = None
        if encrypt or sign:
            if gpg_on:
                if encrypt:
                    data = self._encrypt_gpg_now(data, encrypt, sign)
                elif sign:
                    data, micalg = self._sign_gpg_now(data, sign, send)
            else:
                d = self._encrypt_smime_now(data, sign, encrypt)
                email = BytesParser().parsebytes(d.strip())  # smime always produces a Message object, not raw data
            if (gpg_on and not data) or (not gpg_on and not email):
                logger.error("Signing/encrypting failed.")
                return

        # sending email message object
        self._result.clear()
        self._result_cache = None
        self._result_cache_hash = self._param_hash()
        if send is not None:
            if gpg_on:
                if encrypt:
                    email = self._compose_gpg_encrypted(data)
                elif sign:  # gpg
                    email = self._compose_gpg_signed(email, data, micalg)
            elif encrypt or sign:  # smime
                # smime does not need additional EmailMessage to be included in, just restore Subject that has been
                # consumed in _encrypt_smime_now. It's interesting that I.E. "Reply-To" is not consumed there.
                email["Subject"] = self._subject
            email = self._send_now(email, encrypt, gpg_on, send)
            if not email:
                return

        # output to file or display
        if email or data:
            self._result.append(email if email else assure_fetched(data, str))
            if self._output:
                with open(self._output, "wb") as f:
                    f.write(email.as_bytes() if email else data)
            self._status = True

        return email

    def _determine_gpg(self, encrypt, sign):
        """ determine if we are using gpg or smime"""
        gpg_on = None
        if encrypt or sign:
            if self._gpg is not None:
                gpg_on = bool(self._gpg)
            else:
                gpg_on = True

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
                        result = self._gnupg.import_keys(assure_fetched(sign, bytes))
                        sign = result.fingerprints[0]

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
                                decipherers.extend(self._gnupg.import_keys(assure_fetched(item, bytes)).fingerprints)
                            else:
                                decipherers.append(item)
                        encrypt = decipherers

        return encrypt, sign, gpg_on

    def _get_gnupg_home(self, for_help=False):
        s = self._gpg if type(self._gpg) is str else None
        if for_help:
            return f"GNUPGHOME={s} " if s else ""
        return s

    def _send_now(self, email, encrypt, encrypted_subject, send):
        try:
            if not self._from and self._from is not False and send is True:
                # allow ignoring the `From` header when deliberately set to False
                logger.error("You have to specify From e-mail.")
                return False
            if self._from:
                email["From"] = str(self._from)
            if self._to:
                email["To"] = ",".join(map(str, self._to))
            if self._cc:
                email["Cc"] = ",".join(map(str, self._cc))
            if self._reply_to:
                email["Reply-To"] = ",".join(map(str, self._reply_to))
        except IndexError as e:
            s = set(self._to + self._cc + self._bcc + self._reply_to + [x for x in [self._from] if x])
            logger.error(f"An e-mail address seem to be malformed.\nAll addresses: {s}\n{e}")
            return False

        # insert arbitrary headers
        # XX do not we want to encrypt these headers with GPG/SMIME?
        for k, v in self._headers.items():
            if k.lower() in ("content-type", "content-transfer-encoding", "mime-version"):
                # skip headers already inserted in _prepare_email
                continue
            try:
                email[k] = v
            except TypeError:
                # ex: Using random string with header Date
                raise TypeError(f"Wrong header {k} value: {v}")
        if "Date" not in email and not self._ignore_date:
            email["Date"] = formatdate(localtime=True)
        if "Message-ID" not in email and send != SIMULATION:  # we omit this field when testing
            email["Message-ID"] = make_msgid()

        if send and send != SIMULATION:
            with mock.patch.object(Generator, '_handle_multipart_signed', Generator._handle_multipart):
                # https://github.com/python/cpython/issues/99533 and #19
                failures = self._smtp.send_message(email,
                                                from_addr=self._from_addr,
                                                to_addrs=list(map(str, set(self._to + self._cc + self._bcc))))
            if failures:
                logger.warning(f"Unable to send to all recipients: {repr(failures)}.")
            elif failures is False:
                return False
        else:
            if send != SIMULATION:
                self._result.append(f"{'*' * 100}\nHave not been sent from {(self._from_addr or self._from or '-')}"
                                    f" to {', '.join(self.recipients()) or '-'}")
            if encrypt:
                if encrypted_subject:
                    self._result.append(f"Encrypted subject: {self._subject}")
                self._result.append(f"Encrypted message: {self._message}")
            if len(self._result):  # put an empty line only if some important content was already placed
                self._result.append("")

        return email

    def _param_hash(self):
        """ Check if headers changed from last _start call."""
        return (hash(frozenset(self._headers.items())) + hash("".join(self.recipients()))
                + hash(self._subject) + hash(self._subject_encrypted) + hash(self._from))

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

    def _gpg_list_keys(self, secret=False):
        return ((key, address) for key in self._gnupg.list_keys(secret) for _, address in getaddresses(key["uids"]))

    def _gpg_verify(self, signature:bytes, data:bytes):
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

    def _get_decipherers(self) -> Set[str]:
        """
        :return: Set of e-mail addresses
        """
        return set(x.address for x in self._to + self._cc + self._bcc + [x for x in [self._from] if x])

    def _encrypt_smime_now(self, email, sign, encrypt: Union[None, bool, bytes, List[bytes]]):
        """

        :type encrypt: Can be None, False, bytes or list[bytes]
        """
        with warnings.catch_warnings():
            # m2crypto.py:13: DeprecationWarning: the imp module is deprecated in favour of importlib;
            # see the module's documentation for alternative uses import imp
            warnings.simplefilter("ignore", category=DeprecationWarning)
            try:
                from M2Crypto import BIO, SMIME, X509, EVP  # we save up to 30 - 120 ms to load it here
            except ImportError:
                # noinspection PyPep8Naming
                BIO = SMIME = X509 = EVP = None
                raise ImportError(smime_import_error)
        output_buffer = BIO.MemoryBuffer()
        signed_buffer = BIO.MemoryBuffer()
        content_buffer = BIO.MemoryBuffer(email)

        # Instantiate an SMIME object.
        smime = SMIME.SMIME()

        if sign:
            # Since s.load_key shall not accept file contents, we have to set the variables manually
            sign = assure_fetched(sign, bytes)
            # XX remove getpass conversion to bytes callback when https://gitlab.com/m2crypto/m2crypto/issues/260 is resolved
            cb = (lambda x: bytes(self._passphrase, 'ascii')) if self._passphrase \
                else (lambda x: bytes(getpass(), 'ascii'))
            try:
                smime.pkey = EVP.load_key_string(sign, callback=cb)
            except TypeError:
                raise TypeError("Invalid key")
            if self._cert:
                cert = self._cert
            else:
                cert = sign
            smime.x509 = X509.load_cert_string(cert)
            if not encrypt:
                p7 = smime.sign(content_buffer, SMIME.PKCS7_DETACHED)
                content_buffer = BIO.MemoryBuffer(email)  # we have to recreate it because it was sucked out
                smime.write(output_buffer, p7, content_buffer)
            else:
                p7 = smime.sign(content_buffer)
                smime.write(signed_buffer, p7)
                content_buffer = signed_buffer
        if encrypt:
            sk = X509.X509_Stack()
            if type(encrypt) is not list:
                encrypt = [encrypt]
            [sk.push(X509.load_cert_string(e)) for e in encrypt]
            # XX certificates might be loaded from a directory by from, to, sender:
            # X509.load_cert_string(assure_fetched(e, bytes)).get_subject() ->
            # 'C=CZ, ST=State, L=City, O=Organisation, OU=Unit, CN=my-name/emailAddress=email@example.com'
            # X509.load_cert_string can take 7 µs, so the directory should be cached somewhere.
            smime.set_x509_stack(sk)
            smime.set_cipher(SMIME.Cipher('des_ede3_cbc'))  # Set cipher: 3-key triple-DES in CBC mode.

            # Encrypt the buffer.
            p7 = smime.encrypt(content_buffer)
            smime.write(output_buffer, p7)

        return output_buffer.read()

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

    def _prepare_email(self, plain: bytes, html: bytes, encrypt_gpg: bool, sign_gpg: bool, sign):
        """
        :type sign: If GPG, this should be the key fingerprint.
        """
        # we'll send it later, transform the text to the e-mail first
        msg_text = EmailMessage()
        # XX make it possible to be "plain" here + to have "plain" as the automatically generated html for older browsers
        # XX Should we assure it ends on CRLF? b"\r\n".join(text.splitlines()).decode("utf-8")
        if "MIME-Version" in self._headers:
            msg_text["MIME-Version"] = self._headers["MIME-Version"]
        if "Content-Type" not in self._headers:
            # determine mime subtype and maybe do nl2br
            mime, nl2br = self._mime, self._nl2br

            if plain is None:
                plain, html = html, None
                mime = HTML

            try:
                t: str = plain.decode()
            except UnicodeError:
                raise ValueError("Cannot decode the message correctly, it is not in Unicode."
                                 " Either specify Content-Type and Content-Transfer-Encoding headers manually"
                                 " or pass the message as str.")
            if mime == AUTO:
                if html:
                    mime = PLAIN
                elif get_mimetype(data=t) == "text/html" \
                        or any(x for x in ("<br", "<b>", "<i>", "<p", "<img") if x in t):
                    # magic will determine a short text is HTML if there is '<a href=' but a mere '<br>' is not sufficient.
                    mime = HTML
                else:
                    mime = PLAIN
            if mime == HTML:
                if nl2br == AUTO and not len([x for x in ("<br", "<p") if x in t]):
                    nl2br = True
                if nl2br is True:
                    t = f"<br>{CRLF}".join(t.splitlines())

            # if a line is longer than 1000 characters, force EmailMessage to encode whole message
            if any(line for line in t.splitlines() if len(line) >= 1000):
                # passing bytes to EmailMessage makes its ContentManager to transfer it via base64 or quoted-printable
                # rather than plain text. Which could cause a transferring SMTP server to include line breaks and spaces
                # that might break up DKIM.
                msg_text.set_content(t.encode("utf-8"), maintype="text", subtype=mime)  # text as bytes
                msg_text.set_param("charset", "utf-8", replace=True)
            else:
                msg_text.set_content(t, subtype=mime)  # text as string
        else:
            msg_text["Content-Type"] = self._headers["Content-Type"]
            if "Content-Transfer-Encoding" in self._headers:
                msg_text["Content-Transfer-Encoding"] = self._headers["Content-Transfer-Encoding"]
            # When the user sets Content-Type as multipart, they signalize they want to create sub-message themselves,
            # if they do not do that, the message looks badly. Ex: the text should contain boundaries and sub-messages.
            msg_text.set_payload(plain)

        if html:
            # prefer transferring the HTML alternative as a string,
            # so the source code of the EML is more readable (no Content-Transfer-Encoding is used)
            try:
                # make sure `html` is in Unicode
                html_s = html.decode()
            except UnicodeError:
                raise ValueError("Cannot decode the text/html alternative bytes correctly, it is not in Unicode."
                                 " Pass it as str instead.")
            try:
                # if a line is longer than 1000 characters, force EmailMessage to encode whole message
                if any(line for line in html.splitlines() if len(line) >= 1000):
                    # passing bytes to EmailMessage makes its ContentManager to transfer it via base64 or quoted-printable
                    # rather than plain text. Which could cause a transferring SMTP server to include line breaks and spaces
                    # that might break up DKIM.

                    # create an alternative message part and set utf-8 encoding explicitly
                    alt_msg = EmailMessage()
                    alt_msg.set_content(html_s.encode("utf-8"), maintype="text", subtype="html")  # pass `html` as bytes
                    alt_msg.set_param("charset", "utf-8", replace=True)
                    msg_text.make_alternative()
                    msg_text.attach(alt_msg)
                else:
                    msg_text.add_alternative(html_s, subtype='html')  # `html` as string
            except (ValueError, TypeError):
                # Content-Type: multipart/mixed -> ValueError: Cannot convert mixed to alternative
                # Content-Type: multipart/alternative -> TypeError: Attach is not valid on a message with a non-multipart payload
                raise ValueError("Failed to add HTML alternative to the message. Try not setting Content-Type.")
            else:
                if self._message.boundary:
                    msg_text.set_boundary(self._message.boundary)

        if any(a for a in self._attachments if a.inline):
            # we have to convert the HTML alternative to the multipart/relative content-type.
            # This is either the latter of the two alternatives (if the payload is a list, thus both are specified),
            # or the whole `msg_text` message, if the payload is a mere text (message contents).
            o = msg_text.get_payload()[-1] if isinstance(msg_text.get_payload(), list) else msg_text
            o.make_related()
            [o.add_related(a.data,
                           **dict(zip(("maintype", "subtype"), a.mimetype.split("/"))),
                           cid=f"<{a.name}>") for a in self._attachments if a.inline]

        if self._attach_key:
            # send your public key as an attachment (so that it can be imported before it propagates on the server)
            contents = self._gnupg.export_keys(sign)
            if not contents:
                raise RuntimeError("Cannot attach GPG sign key, not found.")
            self.attach(contents, "public-key.asc")

        failed = False
        [msg_text.add_attachment(a.data,
                                 **dict(zip(("maintype", "subtype"), a.mimetype.split("/"))),
                                 filename=a.name) for a in self._attachments if not a.inline]

        if failed:
            return False
        if encrypt_gpg:  # GPG inner message definition
            # in order to encrypt subject field → encapsulate the message into multipart having rfc822-headers submessage
            email = EmailMessage()
            email.set_type("multipart/mixed")
            email.set_param("protected-headers", "v1")
            # In Thunderbird 68.8 or earlier,
            # encrypted subject worked with "multipart/mixed" directly rather than with "text/rfc822-headers" as tested before.
            # However, I will let the code here for the case it will be needed again in the future or till when we can explain
            # why that worked before and why that stopped working now.
            #
            # msg_headers = EmailMessage()
            # msg_headers.set_param("protected-headers", "v1")
            # msg_headers.set_content(f"Subject: {self._subject}")
            # msg_headers.set_type("text/rfc822-headers")  # must be set after set_content, otherwise reset to text/plain
            #
            # email.attach(msg_headers)
            email["Subject"] = self._subject
            email.attach(msg_text)
        else:  # plain message, smime or gpg-signed message
            email = msg_text
            if not sign_gpg:
                # due to an EmailMessage error (at least at Python3.7)
                # I cannot put diacritics strings like "Test =?utf-8?b?xZnFocW+xZnEjQ==?=" in subject
                # in inner message when GPG signing
                email["Subject"] = self._subject
        return email

    def recipients(self, *, clear=False) -> Union[Set[Address], 'Envelope']:
        """ Return set of all recipients – To, Cc, Bcc
            :param: clear If true, all To, Cc and Bcc recipients are removed and the object is returned.

            Envelope()
                .to("person1@example.com")
                .to("person1@example.com, John <person2@example.com>")
                .to(["person3@example.com"])
                .recipients()  # ["person1@example.com", "John <person2@example.com>", "person3@example.com"]
        """
        if clear:
            self._to.clear()
            self._cc.clear()
            self._bcc.clear()
            return self
        return {x for x in set(self._to + self._cc + self._bcc)}

    def attachments(self, name=None, inline=None) -> Union[Attachment, List[Attachment], bool]:
        """ Access the attachments.
            XX make available from CLI too
                --attachments(-inline)(-enclosed) [name]
            :type name: str Set the name of the only desired attachment to be returned.
            :type inline: bool Filter inline/enclosed attachments only.
            :return Attachment or False when a name is set, otherwise list of all the attachments.
        """
        attachments = [a for a in self._attachments if bool(a.inline) == inline] if inline is not None \
            else self._attachments

        if name is not None:
            for a in attachments:
                if a.name == name:
                    return a
            else:
                return False
        return attachments

    def check(self, check_mx=True, check_smtp=True) -> bool:
        """
        If sender specified, check if DMARC DNS records exist and prints out the information.
        :param check_mx: bool If True, all e-mail addresses are checked for MX record.
        :param check_smtp: bool If True, we try to connect to the SMTP host.
        :rtype: bool All e-mail addresses are valid and SMTP connection worked
        """
        passed = all(address.is_valid(check_mx)
                     for address in self._to + self._cc + self._bcc + self._reply_to + [x for x in [self._from] if x])

        if self._from:
            try:
                domain = self._from.address.split("@")[1]
            except IndexError:
                passed = False
                logger.warning(f"Could not parse domain from the From address '{self._from}'")
            else:
                def dig(query_or_list, rr="TXT"):
                    if type(query_or_list) is not list:
                        query_or_list = [query_or_list]
                    for query in query_or_list:
                        try:
                            text = subprocess.check_output(["dig", "-t", rr, query],
                                                           env=dict(environ, LC_ALL=SAFE_LOCALE)).decode("utf-8")
                            text = text[text.find("ANSWER SECTION:"):]
                            text = text[:text.find(";;")].split("\n")[1:-2]
                            res = []
                            for line in text:
                                # Strip tabs and quotes `_dmarc.gmail.com.\t600\tIN\tTXT\t"v=DMARC1;"` → `v=DMARC1;`
                                res.append(line.split("\t")[-1][1:-1])  #
                        except IndexError:
                            return []
                        else:
                            if res:
                                return res

                def search_start(list_, needle):
                    if list_:
                        for line in list_:
                            if line.startswith(needle):
                                return line

                spf = search_start(dig(domain), "v=spf")
                if not spf:
                    spf = search_start(dig(domain, "SPF"), "v=spf")
                if spf:
                    print(f"SPF found on the domain {domain}: {spf}")
                else:
                    logger.warning(f"SPF not found on the domain {domain}")
                print(f"See: dig -t SPF {domain} && dig -t TXT {domain}")

                dkim = dig(["mx1._domainkey." + domain, "mx._domainkey." + domain, "default._domainkey." + domain])
                if dkim:
                    print(f"DKIM found: {dkim}")
                else:
                    print("Could not spot DKIM. (But I do not know the selector.)")

                dmarc = dig("_dmarc." + domain)
                if dmarc:
                    print(f"DMARC found: {dmarc}")
                else:
                    print("Could not spot DMARC.")

        if check_smtp:
            print("Trying to connect to the SMTP...")
            passed *= bool(self._smtp.connect())  # check SMTP
        return passed

    def smtp_quit(self=None):
        """ Explicitly closes cached SMTP connections. Either class or instance can be called.
        Envelope.smtp_quit() → closing all
        Envelope().smtp_quit() → closing only those which match the SMTP server provided to the Envelope object
        """
        if self is None:
            SMTPHandler.quit_all()
        else:
            self._smtp.quit()
