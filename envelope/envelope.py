#!/usr/bin/env python3
import binascii
import logging
import re
import smtplib
import subprocess
import sys
import tempfile
import warnings
from base64 import b64decode
from configparser import ConfigParser
from copy import copy, deepcopy
from email import message_from_bytes, message_from_string, header
from email.header import decode_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import make_msgid, formatdate, getaddresses
from getpass import getpass
from itertools import chain
from pathlib import Path
from quopri import decodestring
from typing import Union, List, Set, Any

from .utils import Address, Attachment, AutoSubmittedHeader, SMTP, _Message, is_gpg_fingerprint, assure_list, \
    assure_fetched

smime_import_error = "Cannot import M2Crypto. Run: `sudo apt install swig && pip3 install M2Crypto`"

try:
    import gnupg
except ImportError:
    gnupg = None
import magic

__doc__ = """


Quick layer python-gnupg, smime, smtplib and email handling packages.
Their common usecases merged into a single function. Want to sign a text and tired of forgetting how to do it right?
You do not need to know everything about GPG or S/MIME, you do not have to bother with importing keys.
Do not hassle with reconnecting SMTP server. Do not study various headers meanings to let your users unsubscribe via a URL.
You insert a message and attachments and receive signed and/or encrypted output to the file or to your recipients' e-mail. 
Just single line of code. With the great help of the examples below.

Usage:
  * launch as application, see ./envelope.py --help
  * import as a module to your application, ex: `from envelope import Envelope` 

Example:

gpg(message="Hello world",
        output="/tmp/output_file",
        encrypt_file="/tmp/remote_key.asc",
        sender="me@email.com",
        to="remote_person@example.com")
"""

logger = logging.getLogger(__name__)
CRLF = '\r\n'
AUTO = "auto"
PLAIN = "plain"
HTML = "html"
SIMULATION = "simulation"


class Envelope:
    default: 'Envelope'

    _gnupg: gnupg.GPG

    def __bool__(self):
        return self._status

    def __str__(self):
        if self._result_cache_hash and self._result_cache_hash != self._param_hash():
            # ex: if we change Subject, we have to regenerate self._result
            self._result.clear()
        if not self._result:
            if self._encrypt or self._sign:
                # if subject is not set, we suppose this is just a data blob to be encrypted, no an e-mail message
                # and a ciphered blob will get output. However if subject is set, we put send=SIMULATION
                # in order to display all e-mail headers etc.
                is_email = SIMULATION if bool(self._subject) else False
                self._start(send=is_email)
            else:
                # nothing to do, let's assume this is a bone of an e-mail by appending `--send False` flag to produce an output
                self._start(send=SIMULATION)
        return self._get_result_str()

    def __repr__(self):
        """
        :return: Prints out basic representation.
            However this is not serialization, you cannot reconstruct any complicated objects having attachments or custom headers.
        """
        l = []
        quote = lambda x: '"' + x.replace('"', r'\"') + '"' if type(x) is str else x

        text, html = self._message.get()
        message = {}
        if text and html:
            message = {"message(html)": html,
                       "message(plain)": text}
        elif text or html:
            message = {"message": text or html}
        l.extend(f'{k}={quote(v)}' for k, v in {"subject": self._subject,
                                                "from_": self._from,
                                                "to": self._to,
                                                "cc": self._cc,
                                                "bcc": self._bcc,
                                                "reply_to": self._reply_to,
                                                **message
                                                }.items() if v)

        if not l:
            return super().__repr__()
        return f"Envelope({', '.join(l)})"

    def __bytes__(self):
        if not self._result:
            str(self)
        return assure_fetched(self._get_result_str(), bytes)

    def __eq__(self, other):
        if not self._result:
            str(self)
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
        if not self._result:
            str(self)
        result = []
        for a in self._attachments:  # include attachments info as they are removed with the payload later
            if a.inline:
                s = f"Inline attachment {a.preview()}"
            else:
                s = f"Attachment {a.preview()}"
            result.append(s)

        if self._bcc:  # as bcc is not included as an e-mail header, we explicitly states it here
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

        text, html = self._message.get()
        if text and html:
            result.extend(["* MESSAGE VARIANT text/plain:", text, "",
                           "* MESSAGE VARIANT text/html:", html])
        else:
            result.append(self.message())
        return "\n".join(result)

    def _get_result_str(self):
        """ concatenate output string """
        if not self._result_cache:
            s = "\n".join(str(r) for r in self._result)
            self._result_cache = s  # slightly quicker next time if ever containing a huge amount of lines
        return self._result_cache

    def as_message(self) -> Message:
        """
        :return: Message object is S/MIME is used, EmailMessage otherwise.
        """
        for el in self._result:
            if isinstance(el, Message):
                return el
        return self._start(send=SIMULATION)

    @staticmethod
    def load(message=None, *, path=None, key=None, cert=None) -> "Envelope":
        """
        XX make it capable to verify signatures
        XX option to specify the GPG decrypting key
        XX make key and cert work from bash too and do some tests

        Note that if you will send this reconstructed message, you might not probably receive it due to the Message-ID duplication.
        Delete at least Message-ID header prior to re-sending.

        :param message: Any attainable contents to build an Envelope object from, including email.message.Message.
        :param path: (Alternative to `message`.) Path to the file that should be loaded.
        :param key: S/MIME key to decrypt with.
        :param cert: S/MIME cert to decrypt with. (If not bundled with the key.)
        """
        if path:
            message = Path(path)
        elif isinstance(message, Message):
            message = str(message)

        o = message_from_bytes(assure_fetched(message, bytes))
        e = Envelope()
        try:
            return Parser(e, key=key, cert=cert, gnupg_home=e._get_gnupg_home()).parse(o, add_headers=True)
        except ValueError as err:
            logger.warning(f"Message might not have been loaded correctly. {err}")
            import ipdb; ipdb.post_mortem()

        # emergency body loading when parsing failed
        header_row = re.compile(r"([^\t:]+):(.*)")
        text = assure_fetched(message, str)
        is_header = True
        header = []  # [whole line, header name, header val] XX header is not used, deprecated
        body = []
        for line in text.splitlines():
            if is_header:  # we are parsing e-mail template header first
                # are we still parsing the header?
                m = header_row.match(line)
                if m:
                    header.append([line, m.group(1).strip(), m.group(2).strip()])
                    continue
                else:
                    if line.startswith(("\t", " ")) and header:  # this is not end of header, just line continuation
                        header[-1][0] += " " + line.strip()
                        header[-1][2] += " " + line.strip()
                        continue
                    is_header = False  # header has ended
                    if line.strip() == "":  # next line will be body
                        continue
                    else:  # header is missing or incorrect, there is body only
                        body = [l[0] for l in header]
                        header = []
            if not is_header:
                body.append(line)

        e.message(CRLF.join(body))
        # for _, key, val in header:
        #     e.header(key, val)
        return e

    def __init__(self, message=None, from_=None, to=None, subject=None, headers=None,
                 gpg=None, smime=None,
                 encrypt=None, sign=None, passphrase=None, attach_key=None, cert=None,
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
        :param passphrase: If signing key needs passphrase.
        :param attach_key: If True, public key is appended as an attachment.
        :param cert: S/MIME certificate contents or Path or stream (ex: from open()) if certificate not included in the key.

        Encrypting
        :param encrypt: Recipients public key string or Path or stream (ex: from open()).
        :param to: E-mail or list. If encrypting used so that we choose the key they will be able to decipher with.
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
        :param cc: E-mail or their list.
        :param bcc: E-mail or their list.
        :param attachments: Attachment or their list. Attachment is defined by file path or stream (ex: from open()),
            optionally in tuple with the file name in the e-mail and/or mimetype.
        :param headers: List of headers which are tuples of name, value. Ex: [("X-Mailer", "my-cool-application"), ...]
        :param sender: Alias for "from" if not set. Otherwise appends header "Sender".
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
        self._from: Union[Address, False] = None
        self.__from: Union[Address, False] = None
        self._sender: Union[Address, False] = None
        self.__sender: Union[Address, False] = None
        self._to: List[Address] = []
        self._cc: List[Address] = []
        self._bcc: List[Address] = []
        self._reply_to: List[Address] = []
        self._subject: str = None
        self._smtp = None
        self._attachments: List[Attachment] = []
        self._mime = AUTO
        self._nl2br = AUTO
        self._headers = EmailMessage()  # object for storing headers the most standard way possible
        self._ignore_date = False

        # variables defined while processing
        self._status = False  # whether we successfully encrypted/signed/send
        self._processed = False  # prevent the user from mistakenly call .sign().send() instead of .signature().send()
        self._result = []  # text output for str() conversion
        self._result_cache = None
        self._result_cache_hash = None
        self._smtp = SMTP()
        self.auto_submitted = AutoSubmittedHeader(self)  # allows fluent interface to set header

        # if a parameter is not set, use class defaults, else init with parameter
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
                if not hasattr(self, "default"):
                    continue
                v = copy(getattr(self.default, self._get_private_var(k)))  # ex `v = copy(self.default._message)`
                if v is None or type(v) is _Message and v.is_empty():  # the default value is empty
                    continue

            if k == "passphrase":
                self.signature(passphrase=v)
            elif k == "attach_key":
                if v is True:
                    self.signature(attach_key=v)
            elif k == "cert":
                self.signature(None, cert=v)
            elif k == "attachments":
                self.attach(v)
            elif k == "headers":  # [(header-name, val), ...]
                for it in v:
                    self.header(*it)
            elif k == "sign":
                self.signature(v)
            elif k == "encrypt":
                self.encryption(v)
            elif k == "_Message":  # internal stuff
                continue
            elif v is not None and v != []:  # "to" will receive [] by default
                getattr(self, k)(v)  # ex: self.message(message)

        self._prepare_from()
        if params.get("sign") or params.get("encrypt") or params.get("send") is not None:
            self._start(send=params.get("send"))
        return self

    def copy(self):
        """ Returns deep copy of the object. """
        return deepcopy(self)

    @staticmethod
    def _parse_addresses(registry, email_or_list):
        addresses = assure_list(email_or_list)
        if any(not x for x in addresses):
            registry.clear()
        addresses = [x for x in addresses if x]  # filter out possible "" or False
        if addresses:
            registry += (a for a in Address.parse(addresses) if a not in registry)

    def to(self, email_or_list=None) -> Union["Envelope", List[Address]]:
        """ Multiple addresses may be given in a string, delimited by comma (or semicolon).
         (The same is valid for `to`, `cc`, `bcc` and `reply-to`.)

            :param email_or_list: str|List[str] Set e-mail address/es. If None, we are reading.
            return: Envelope if `email_or_list` set or List[Address]
        """
        if email_or_list is None:
            return self._to
        self._parse_addresses(self._to, email_or_list)
        return self

    def cc(self, email_or_list=None) -> Union["Envelope", List[Address]]:
        if email_or_list is None:
            return self._cc
        self._parse_addresses(self._cc, email_or_list)
        return self

    def bcc(self, email_or_list=None) -> Union["Envelope", List[Address]]:
        if email_or_list is None:
            return self._bcc
        self._parse_addresses(self._bcc, email_or_list)
        return self

    def reply_to(self, email_or_list=None) -> Union["Envelope", List[Address]]:
        if email_or_list is None:
            return self._reply_to
        self._parse_addresses(self._reply_to, email_or_list)
        return self

    def body(self, text=None, *, path=None):
        """ An alias of .message """
        return self.message(text=text, path=path)

    def text(self, text=None, *, path=None):
        """ An alias of .message """
        return self.message(text=text, path=path)

    def message(self, text=None, *, path=None, alternative=AUTO, boundary=None) -> Union["Envelope", Any]:
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

        :return: Envelope if text or path is set
            else return anything that has been inserted to the .message() before (probably str, bytes)
        """
        # XX make preview default over send(0) when no action is given?
        if boundary is not None:
            self._message.boundary = boundary
        if alternative not in (AUTO, PLAIN, HTML):
            raise ValueError(f"Invalid alternative {alternative} for message, choose one of the: {AUTO}, {PLAIN}, {HTML}")
        if text is path is None:
            # reading value
            s = getattr(self._message, alternative)
            if not s and alternative == AUTO:  # prefer reading HTML over plain text if alternative set
                s = self._message.html or self._message.plain

            transfer = self._headers.get("Content-Transfer-Encoding")
            # Useful for reading loaded EML that might have been encoded.
            # When loading an EML, everything was loaded into `self._message.auto`.
            # XX When loading an EML, everything is under .auto so that quering alternative="html"|"plain" would return None here!
            if transfer == "base64":
                try:
                    return b64decode(s).decode("utf-8")
                except binascii.Error:
                    pass
                except UnicodeDecodeError:
                    raise TypeError(f"Cannot base64-decode the message: {s}")
            elif transfer == "quoted-printable":
                try:
                    return decodestring(s).decode("utf-8")
                except ValueError:
                    pass

            # XX this should return str or bytes
            # We prefer string. But we want to keep it as encoding agnostic as possible so bytes might be better.
            return s or ""  # `s` might be None

        # write value
        if type(text) is _Message:  # constructor internally adopts default's self.default._message
            self._message: _Message = text
            return self

        if path:
            text = Path(path)

        setattr(self._message, alternative, assure_fetched(text, str))
        return self

        # self._message = text
        # return self

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

    def sender(self, email=None) -> Union["Envelope", Address]:
        """  Alias for "from" if not set. Otherwise appends header "Sender". If None, current `Sender` returned. """
        if email is None:
            return self.__sender
        self._sender = Address.parse(email, single=True, allow_false=True)
        self._prepare_from()
        return self

    def from_(self, email=None) -> Union["Envelope", Address]:
        if email is None:
            return self.__from
        self._from = Address.parse(email, single=True, allow_false=True)
        self._prepare_from()
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

    def subject(self, subject=None) -> Union["Envelope", str]:
        if subject is None:
            return str(self._subject or "")
        self._subject: str = subject
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

    def header(self, key, val=None, replace=False):
        """ Add a generic header.
        The header will not be encrypted with GPG nor S/MIME.
        :param key: str Header name
        :param val: str Header value. If None, currently used value is returned.
        :param replace: bool If True, any header of the `key` name are removed first and if `val` is None, the header is deleted.
                        Otherwise another header of the same name is appended.
        :return: Envelope|str|list Returned self if `val` is not None or replace=True, else returns value of the header
                 or its list if the header was used multiple times. (Note that cc and bcc headers always return list.)
        """

        # lowercase header to its method name
        specific_interface = {"to": self.to, "cc": self.cc, "bcc": self.bcc, "reply-to": self.reply_to,
                              "from": self.from_, "sender": self.sender,
                              "subject": self.subject
                              }

        k = key.lower()

        if k in specific_interface:
            if replace:
                attr = getattr(self, self._get_private_var(k))
                setattr(self, self._get_private_var(k), None if type(attr) is str else [])
                if k in ("sender", "from"):
                    self._prepare_from()
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
            self._headers[key] = val
        return self

    def smtp(self, host="localhost", port=25, user=None, password=None, security=None):
        """
        Obtain SMTP server connection.
        Note that you may safely call this in a loop,
            envelope will remember the settings and connect only once (without reconnecting every iteration).
        :param host: hostname, smtplib.SMTP or INI file path.
        :param port:
        :param user:
        :param password:
        :param security: Ex: tlsstart
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

        if type(host) is SMTP:  # constructor internally adopts default's self.default._smtp
            self._smtp = host
        elif type(host) is dict:  # ex: {"host": "localhost", "port": 1234}
            self._smtp = SMTP(**host)
        elif type(host) is list:  # ex: ["localhost", 1234]
            self._smtp = SMTP(*host)
        elif isinstance(host, smtplib.SMTP):
            self._smtp = SMTP(host)
        else:
            self._smtp = SMTP(host, port, user, password, security)
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
        if type(attachment) is list:
            if path or mimetype or name:
                raise ValueError("Cannot specify both path, mimetype or name and put list in attachment_or_list.")
        else:
            if path:
                attachment = Path(path)
            attachment = attachment, mimetype, name, inline
        self._attachments += [Attachment(o) for o in assure_list(attachment)]
        return self

    def signature(self, key=True, passphrase=None, attach_key=None, cert=None, *, key_path=None):
        """
        Turn signing on.
        :param key: Signing key
            * GPG:
                * True (blank) for user default key
                * key ID/fingerprint
                * Any attainable contents with the key to be signed with (will be imported into keyring)
                * "auto" for turning on signing if there is a key matching to the "from" header
            * S/MIME: Any attainable contents with key to be signed with. May contain signing certificate as well.
        :param passphrase: Passphrase to the key if needed.
        :param attach_key: GPG: Append public key to the attachments when sending.
        :param cert: S/MIME: Any attainable contents with certificate to be signed with.
        :param key_path: Path to a file with the `key`.
        """
        if key_path:
            key = Path(key_path)
        if key is True and self._sign not in [None, False]:
            # usecase envelope().signature(key=fingerprint).send(sign=True) should still have fingerprint in self._sign
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
                * True (blank) for user default key
                * key ID/fingerprint
                * Any attainable contents with the key to be signed with (will be imported into keyring)
                * "auto" for turning on signing if there is a key matching to the "from" header
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
                * True (blank) for user default key
                * key ID/fingerprint
                * Any attainable contents with the key to be signed with (will be imported into keyring)
                * "auto" for turning on encrypting if there is a matching key for every recipient
            * S/MIME any attainable contents with certificate to be encrypted with or their list
        :param key_path: Path to a file with the `key` or their list.
        """
        if key_path:
            if type(key_path) is list:
                key = [Path(k) for k in key_path]
            else:
                key = Path(key_path)
        if key is True and self._encrypt not in [None, False]:
            # usecase envelope().encrypt(key="keystring").send(encrypt=True) should still have key in self._encrypt
            # (and not just "True")
            pass
        elif key is not None:
            # possible types: True, AUTO, str, bytes, list of bytes
            self._encrypt = [assure_fetched(k, bytes) for k in key] if isinstance(key, list) else assure_fetched(key)
        return self

    def encrypt(self, key=True, sign=None, *, key_path=None):
        """
        Encrypt now.
        :param key:
            * GPG:
                * True (blank) for user default key
                * key ID/fingerprint
                * Any attainable contents with the key to be signed with (will be imported into keyring)
                * "auto" for turning on encrypting if there is a matching key for every recipient
            * S/MIME any attainable contents with certificate to be encrypted with or their list
        :param sign: Turn signing on.
            * GPG: True or default signing key ID/fingerprint.
            * S/MIME: Any attainable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use .signature() method.)
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
            * GPG: True or default signing key ID/fingerprint.
            * S/MIME: Any attainable contents having the key + signing certificate combined in a single file.
              (If not in a single file, use .signature() method.)
        :param encrypt: Any attainable contents with recipient GPG public key or S/MIME certificate to be encrypted with.
        :return:
        """
        if self._processed:
            raise RuntimeError("Cannot call .send() after .sign()/.encrypt()."
                               " You probably wanted to use .signature()/.encryption() instead.")
        self._start(sign=sign, encrypt=encrypt, send=send)
        return self

    def _prepare_from(self):
        """ Prepare private variables. Resolve "from" and "sender" headers.

        Due to a keyword clash we cannot use "from" as a method name and it seems convenient then to allow users
        to use sender instead. However we do not want to block setting "Sender" header too – since sender is a real header,
        we should somehow distinguish 'sender' from 'from'.
        Pity that 'from' is a reserved keyword, "from_" looks bad.
        """
        if self._from is None and self._sender is not None:
            self.__from = self._sender
            self.__sender = None
        else:
            self.__from = self._from
            self.__sender = self._sender

    def _start(self, sign=None, encrypt=None, send=None):
        """ Start processing. Either sign, encrypt or send the message and possibly set bool status of the object to True.
        * send == SIMULATION is the same as send == False but the message "have not been sent" will not be produced
        """
        text: str
        html: str
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
        text, html = self._message.get()

        # we need a message
        if not any((text, html)):
            logger.error("Missing message")
            return

        # determine if we are using gpg or smime
        encrypt, sign, gpg_on = self._determine_gpg(encrypt, sign)

        # if we plan to send later, convert text message to the email message object
        email = None
        if send is not None or html:  # `html` means the user wants a 'multipart/alternative' e-mail message
            email = self._prepare_email(text, html, encrypt and gpg_on, sign and gpg_on, sign)
            if not email:
                return
            data = email.as_bytes()
        else:
            data = text.encode("utf-8")

        # with GPG, encrypt or sign either text message or email message object
        micalg = None
        if encrypt or sign:
            if gpg_on:
                if encrypt:
                    data = self._encrypt_gpg_now(data, sign)
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
                                        verbose=False) if sign or encrypt else None
                # assure `sign` become either fingerprint of an imported key or None
                if sign:
                    if sign in [True, AUTO]:  # try to determine sign based on the "From" header
                        fallback_sign = sign = None
                        try:
                            address_searched = self.__from.address
                        except AttributeError:
                            # there is no "From" header and no default key is given, pick the first secret as a default
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
                    elif not is_gpg_fingerprint(sign):  # sign is Path or key contents, import it and get its fingerprint
                        result = self._gnupg.import_keys(assure_fetched(sign, bytes))
                        sign = result.fingerprints[0]

                if encrypt:
                    if encrypt == AUTO:
                        # encrypt = True only if there exist a key for every needed address
                        addresses_searched = self._get_decipherers()
                        [addresses_searched.discard(address) for _, address in self._gpg_list_keys(False)]
                        if addresses_searched:
                            encrypt = False
                    elif encrypt is not True and not is_gpg_fingerprint(encrypt):
                        # XX multiple keys in list may be allowed
                        self._gnupg.import_keys(assure_fetched(encrypt, bytes))
        return encrypt, sign, gpg_on

    def _get_gnupg_home(self, readable=False):
        return self._gpg if type(self._gpg) is str else ("default" if readable else None)

    def _send_now(self, email, encrypt, encrypted_subject, send):
        try:
            if not self.__from and send is True:
                logger.error("You have to specify sender e-mail.")
                return False
            if self.__from:
                email["From"] = str(self.__from)
            if self._to:
                email["To"] = ",".join(map(str, self._to))
            if self._cc:
                email["Cc"] = ",".join(map(str, self._cc))
            if self._reply_to:
                email["Reply-To"] = ",".join(map(str, self._reply_to))
        except IndexError as e:
            s = set(self._to + self._cc + self._bcc + self._reply_to)
            if self.__from:
                s.add(self.__from)
            logger.error(f"An e-mail address seem to be malformed.\nAll addresses: {s}\n{e}")
            return False

        # insert arbitrary headers
        # XX do not we want to encrypt these headers with GPG/SMIME?
        for k, v in self._headers.items():
            # XXX check e-mail headers are really case insensitive when loading, add tests
            # if k in ["Content-Type", "Content-Transfer-Encoding", "MIME-Version"]:
            if k.lower() in ["content-type", "content-transfer-encoding", "mime-version"]:
                # skip headers already inserted in _prepare_email
                continue
            try:
                email[k] = v
            except TypeError:
                # ex: Using random string with header Date
                raise TypeError(f"Wrong header {k} value: {v}")
        if self.__sender:
            email["Sender"] = str(self.__sender)
        if "Date" not in email and not self._ignore_date:
            email["Date"] = formatdate(localtime=True)
        if "Message-ID" not in email and send != SIMULATION:  # we omit this field when testing
            email["Message-ID"] = make_msgid()

        if send and send != SIMULATION:
            failures = self._smtp.send_message(email, to_addrs=list(map(str, set(self._to + self._cc + self._bcc))))
            if failures:
                logger.warning(f"Unable to send to all recipients: {repr(failures)}.")
            elif failures is False:
                return False
        else:
            if send != SIMULATION:
                self._result.append(f"{'*' * 100}\nHave not been sent from {(self.__from or '-')}"
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
        return hash(frozenset(self._headers.items())) + hash("".join(self.recipients())) + hash(self._subject) + hash(self.__from)

    def _sign_gpg_now(self, message, sign, send):
        status = self._gnupg.sign(
            message,
            extra_args=["--textmode"],
            # textmode: Enigmail had troubles to validate even though signature worked in CLI https://superuser.com/questions/933333
            keyid=sign,
            passphrase=self._passphrase if self._passphrase else None,
            detach=True if send is not None else None,
        )
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
            logger.error(status.stderr)
            return False, None
        return status.data, micalg

    def _encrypt_gpg_now(self, message, sign_fingerprint):
        exc = []
        if not any(chain(self._to, self._cc, self._bcc)):
            exc.append("No recipient e-mail specified")
        if self.__from is None:
            exc.append("No sender e-mail specified. If not planning to decipher later, put sender=False or --no-sender flag.")
        if exc:
            raise RuntimeError("Encrypt key present. " + ", ".join(exc))
        status = self._gnupg.encrypt(
            data=message,
            recipients=self._get_decipherers(),
            sign=sign_fingerprint if sign_fingerprint else None,
            passphrase=self._passphrase if self._passphrase else None
        )
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
            if any(s in status.stderr for s in ["No name", "No data", "General error", "Syntax error in URI"]):
                keys = [uid["uids"] for uid in self._gnupg.list_keys()]
                found_missing = False
                for identity in self._get_decipherers():
                    if not [k for k in keys if any(x for x in k if identity in x)]:
                        found_missing = True
                        logger.warning(f"Key for {identity} seems missing.")
                if found_missing:
                    s = self._get_gnupg_home()
                    s = f" GNUPGHOME={s}" if s else ""
                    logger.warning(f"See{s} gpg --list-keys")
            return False

    def _gpg_list_keys(self, secret=False):
        return ((key, address) for key in self._gnupg.list_keys(secret) for _, address in getaddresses(key["uids"]))

    def _get_decipherers(self) -> Set[str]:
        """
        :return: Set of e-mail addresses
        """
        return set(x.address for x in self._to + self._cc + self._bcc + ([self.__from] if self.__from else []))

    def _encrypt_smime_now(self, email, sign, encrypt):
        """

        :type encrypt: Union[None, False, bytes, list[bytes]]
        """
        with warnings.catch_warnings():
            # m2crypto.py:13: DeprecationWarning: the imp module is deprecated in favour of importlib;
            # see the module's documentation for alternative uses import imp
            warnings.simplefilter("ignore", category=DeprecationWarning)
            try:
                from M2Crypto import BIO, Rand, SMIME, X509, EVP  # we save up to 30 - 120 ms to load it here
            except ImportError:
                raise ImportError(smime_import_error)
        output_buffer = BIO.MemoryBuffer()
        signed_buffer = BIO.MemoryBuffer()
        content_buffer = BIO.MemoryBuffer(email)

        # Seed the PRNG.
        temp = str(Path(tempfile.gettempdir(), 'envelope-randpool.dat'))
        Rand.load_file(temp, -1)

        # Instantiate an SMIME object.
        smime = SMIME.SMIME()

        if sign:
            # Since s.load_key shall not accept file contents, we have to set the variables manually
            sign = assure_fetched(sign, bytes)
            # XX remove getpass conversion to bytes callback when https://gitlab.com/m2crypto/m2crypto/issues/260 is resolved
            cb = (lambda x: bytes(self._passphrase, 'ascii')) if self._passphrase else (lambda x: bytes(getpass(), 'ascii'))
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

        Rand.save_file(temp)
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

    @staticmethod
    def _compose_gpg_encrypted(text):
        # encrypted message structure according to RFC3156
        email = EmailMessage()
        email["Subject"] = "Encrypted message"  # real subject should be revealed when decrypted
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

    def _prepare_email(self, text: str, html: str, encrypt_gpg, sign_gpg, sign):
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

            if text is None:
                text, html = html, None
                mime = HTML

            t: str = text
            if mime == AUTO:
                if html:
                    mime = PLAIN
                elif magic.Magic(mime=True).from_buffer(t) == "text/html" \
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
            msg_text.set_payload(text, "utf-8")
            # msg_text.add_alternative(text, "utf-8")

        if html:
            try:
                # if a line is longer than 1000 characters, force EmailMessage to encode whole message
                if any(line for line in html.splitlines() if len(line) >= 1000):
                    # passing bytes to EmailMessage makes its ContentManager to transfer it via base64 or quoted-printable
                    # rather than plain text. Which could cause a transferring SMTP server to include line breaks and spaces
                    # that might break up DKIM.

                    # create an alternative message part and set utf-8 encoding explicitly
                    alt_msg = EmailMessage()
                    alt_msg.set_content(html.encode("utf-8"), maintype="text", subtype="html")  # `html` as bytes
                    alt_msg.set_param("charset", "utf-8", replace=True)
                    msg_text.make_alternative()
                    msg_text.attach(alt_msg)
                else:
                    msg_text.add_alternative(html, subtype='html')  # `html` as string
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
            # encrypted subject worked with "multipart/mixed" directly rather then with "text/rfc822-headers" as tested before.
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

    def recipients(self, *, clear=False) -> Set[Address]:
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

    def attachments(self, name=None, inline=None) -> Union[Attachment, List[Attachment]]:
        """ Access the attachments.
            XX make available from CLI too
                --attachments(-inline)(-enclosed) [name]
            :type name: str Set the name of the only desired attachment to be returned.
            :type inline: bool Filter inline/enclosed attachments only.
            :return Attachment when a name is set, otherwise list of all the attachments.
        """
        attachments = [a for a in self._attachments if bool(a.inline) == inline] if inline is not None else self._attachments

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
                     for address in self._to + self._cc + self._bcc + self._reply_to +
                     [x for x in (self.__from, self.__sender) if x])

        if self.__from:
            try:
                domain = self.__from.address.split("@")[1]
            except IndexError:
                passed = False
                logger.warning(f"Could not parse domain from the sender address '{self.__from}'")
            else:
                def dig(query_or_list, rr="TXT", search_start=None):
                    if type(query_or_list) is not list:
                        query_or_list = [query_or_list]
                    for query in query_or_list:
                        try:
                            text = subprocess.check_output(["dig", "-t", rr, query]).decode("utf-8")
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


class Parser:

    def __init__(self, envelope: Envelope = None, key=None, cert=None, gnupg_home=None):
        self.e = envelope
        self.key = key
        self.cert = cert
        self.gnupg_home = gnupg_home

    def parse(self, o: Message, add_headers=False):
        if add_headers:
            for k, val in o.items():
                # XXX
                # print(k, val)
                # import ipdb; ipdb.set_trace()
                # We skip "Content-Type" and "Content-Transfer-Encoding" because we decode text payload before importing.
                # We skip MIME-Version because it may be another one in a encrypted sub-message we take the headers from too.
                if k.lower() in ("content-type", "content-transfer-encoding", "mime-version"):
                    continue
                try:
                    if isinstance(val, header.Header):
                        # when diacritics appear in Subject, object is returned instead of a string
                        # when maxline is not set, it uses a default one (75 chars?) and gets encoded into multiple chunks
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
                    if p.get_content_maintype() in ["text", "multipart"] and p.get_content_disposition() != "attachment":
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
                    t = t.decode(o.get_charsets()[0])
                self.e.message(t, alternative=subtype)
            else:
                raise ValueError(f"Unknown subtype: {subtype}")
        elif maintype == "application" and subtype == "x-pkcs7-mime":  # decrypting S/MIME
            self.parse(message_from_bytes(self.smime_decrypt(o.as_bytes())), add_headers=True)
        else:
            raise ValueError(f"Unknown maintype: {maintype}")
        return self.e

    def gpg_decrypt(self, data):
        g = gnupg.GPG(gnupghome=self.gnupg_home)
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
