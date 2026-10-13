#!/usr/bin/env python3
from json import loads
import logging
import re
from copy import deepcopy
from email import message_from_bytes
from email.header import decode_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path
from typing import Literal, Union, Optional, overload

from .address import Address
from .attachment import Attachment
from ._addressing import _AddressingMixin
from ._content import _ContentMixin
from ._signing import _SigningMixin
from ._encryption import _EncryptionMixin
from ._delivery import _DeliveryMixin
from .constants import ISSUE_LINK, gnupg, CRLF, AUTO, PLAIN, HTML, SIMULATION
from .message import _Message
from .parser import Parser
from .smtp_handler import SMTPHandler
from .utils import AutoSubmittedHeader, assure_fetched, get_mimetype, message_as_string


__doc__ = """Quick layer over python-gnupg, cryptography, smtplib, magic and email handling packages.
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


class Envelope(_AddressingMixin, _ContentMixin, _SigningMixin, _EncryptionMixin, _DeliveryMixin):
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
            s = "\n".join(message_as_string(r) for r in self._result)  # #19
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

        :raise ValueError: If the message cannot be loaded.
        """
        if path:
            message = Path(path)
        elif isinstance(message, Message):
            message = str(message)

        msg_ = assure_fetched(message, bytes)
        o = message_from_bytes(msg_)

        # NOTE this breaks up .load("hello text")
        # quick check
        for _ in o.keys():
            break
        else:  # there are no headers
            if not path and b"\n" not in msg_ and b"\r" not in msg_:
                raise ValueError(f"Message cannot be loaded. Didn't you forgot to use the `Envelope.load(path=...)`?")

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
                 smtp=None, sendmail=None, output=None, send=None):
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
            Or False to not use SMTP.
        :param sendmail: True or path to ubiquitious sendmail binary.
            Otherwise the standard "/usr/sbin/sendmail" is used.
            Sendmail is only used if this method OR smtp(False) is called
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
        self._to: list[Address] = []
        self._cc: list[Address] = []
        self._bcc: list[Address] = []
        self._reply_to: list[Address] = []
        self._subject: Union[str, None] = None
        self._subject_encrypted: Union[str, bool] = True
        self._attachments: list[Attachment] = []
        self._mime = AUTO
        self._nl2br = AUTO
        self._headers = EmailMessage()  # object for storing headers the most standard way possible
        self._ignore_date: bool = False

        # variables defined while processing
        self._status: bool = False  # whether we successfully encrypted/signed/send
        self._processed: bool = False  # prevent the user from mistakenly call .sign().send() instead of .signature().send()
        self._result: list[Union[str, EmailMessage, Message]] = []  # text output for str() conversion
        self._result_cache: Optional[str] = None
        self._result_cache_hash: Optional[int] = None
        self._smtp: Union[SMTPHandler, bool] = SMTPHandler()
        self._sendmail: Union[str, bool, None, Path] = False
        self.auto_submitted = AutoSubmittedHeader(self)  # allows fluent interface to set header

        self._multipart_report_message: Optional[Message] = None

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

    def sender(self, email=None):
        """ REMOVED, raises an informative error. Use Envelope().from_() or Envelope().header("Sender", ...) instead."""
        raise NotImplementedError("Method Envelope().sender() has been deprecated and was removed due"
                                  " to the unambiguous naming clash between the From and the Sender e-mail header."
                                  ' Use Envelope().from_(...) and Envelope().header("Sender", ...) instead.')

    def output(self, output_file):
        self._output = output_file
        return self

    auto_submitted: AutoSubmittedHeader

    @overload
    def header(self, key: str, val: None = None, replace: Literal[False] = False) -> Union[str, list, Address, None]: ...

    @overload
    def header(self, key: str, val: str, replace: bool = False) -> "Envelope": ...

    @overload
    def header(self, key: str, val: None, replace: Literal[True]) -> "Envelope": ...

    @overload
    def header(self, key: str, val: Optional[str] = None, replace: bool = False) -> Union["Envelope", list, str, Address, None]: ...

    def header(self, key, val=None, replace=False) -> Union["Envelope", list, str, None]:
        """ Add a generic header.
        The header will not be encrypted with GPG nor S/MIME.
        :param key: str Header name
        :param val: str Header value. If None, currently used value is returned as string, or their list, or None.
        :param replace: bool If True, any header of the `key` name are removed first and if `val` is None, the header is deleted.
                        Otherwise another header of the same name is appended.
        :return: Envelope|str|list|None Returned self if `val` is not None or replace=True, else returns value of the header
                 or its list if the header was used multiple times. (Note that cc and bcc headers always return list.)

        Special case: the headers To, Cc, Bcc, Reply-To, From and Subject (case-insensitive) are not stored
        as generic headers. They are delegated to their dedicated methods `.to()`, `.cc()`, `.bcc()`, `.reply_to()`,
        `.from_()` and `.subject()`, so they behave exactly like those (ex: the Subject can be encrypted).
        That makes their return values differ from the generic headers:
            * reading To/Cc/Bcc/Reply-To returns `list[Address]` (even for a single address, even when empty),
              From returns an `Address`, Subject returns a `str` (instead of the `str|list|None` of generic headers)
            * setting To/Cc/Bcc/Reply-To appends to the current addresses, setting From/Subject overwrites it
            * an RFC 2047 encoded value (ex: `=?UTF-8?Q?...?=`) is decoded before it is passed to the method
            * replace=True clears the field first, then sets the `val` if given
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
                if val is None:
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
                chunks = []
                for part, encoding in decode_header(val):
                    if isinstance(part, bytes):
                        chunks.append(part.decode(encoding if encoding not in ('unknown-8bit', None) else 'utf-8'))
                    else:
                        chunks.append(part)
                val = "".join(chunks)
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
        email: Optional[Union[str, EmailMessage, Message]] = None
        if send is not None or html or self._attachments:  # `html` or attachments means the user needs a 'multipart/...' e-mail message
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

    def _param_hash(self):
        """ Check if headers changed from last _start call."""
        return (hash(frozenset(self._headers.items())) + hash("".join(self.recipients()))
                + hash(self._subject) + hash(self._subject_encrypted) + hash(self._from))

    def _prepare_email(self, plain: bytes, html: bytes, encrypt_gpg: bool, sign_gpg: bool, sign):
        """
        :type sign: If GPG, this should be the key fingerprint.
        """
        msg_text, html = self._compose_body(plain, html)
        if html:
            self._add_html_alternative(msg_text, html)
        self._add_attachments(msg_text, sign)
        return self._wrap_inner_message(msg_text, encrypt_gpg, sign_gpg)

    def _compose_body(self, plain: bytes, html: bytes) -> tuple[EmailMessage, Optional[bytes]]:
        """ The message text part (plain or HTML), or the raw payload if the user has set Content-Type.
        :return: (message, HTML alternative still to be added) – if there is no plain text, HTML becomes the main part.
        """
        # we'll send it later, transform the text to the e-mail first
        msg_text = EmailMessage()
        # XX make it possible to be "plain" here + to have "plain" as the automatically generated html for older browsers
        # XX Should we assure it ends on CRLF? b"\r\n".join(text.splitlines()).decode("utf-8")
        #   (or rather by EmailMessage(policy)
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
        return msg_text, html

    def _add_html_alternative(self, msg_text: EmailMessage, html: bytes):
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

    def _add_attachments(self, msg_text: EmailMessage, sign):
        """ Inline attachments go to a multipart/related part, the others are enclosed. """
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

        [msg_text.add_attachment(a.data,
                                 **dict(zip(("maintype", "subtype"), a.mimetype.split("/"))),
                                 filename=a.name) for a in self._attachments if not a.inline]

    def _wrap_inner_message(self, msg_text: EmailMessage, encrypt_gpg: bool, sign_gpg: bool) -> EmailMessage:
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

    def _report(self) -> Union[dict, None]:
        """ Experimental API, hence private.
            Works just for reading XARF reports.
            Writing might be implemented.
        """
        if not self._multipart_report_message:
            return False

        # reading XARF report http://xarf.org/
        if dict(self._multipart_report_message.get_payload()[0]).get('Feedback-Type') == "xarf":
            return loads(self.attachments("xarf.json").data)

        raise NotImplemented("Current multipart/report has not been impemented."
                             f"Please post current message as a new issue at {ISSUE_LINK}")
